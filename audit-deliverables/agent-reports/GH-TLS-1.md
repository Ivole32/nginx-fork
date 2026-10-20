# GH-TLS-1 — Variant analysis, remediation and regression test for TLS-1

Agent G (variant analysis) + Agent H (remediation & regression). Revision b38c9d8
(1.31.8 dev). All line numbers verified against `/home/user/nginx-fork` (read-only);
the patched build is a copy under
`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-tls1/`.
OpenSSL 3.0.13, loopback ports 19000-19003.

Parent finding TLS-1: in `ngx_http_set_virtual_server()` the "requested server name
differs from the negotiated one -> 421" guard is enclosed in `if (hc->ssl_servername)`,
so when the client omits SNI (or sends an SNI matching no server) the handshake runs
under the listen default server's `SSL_CTX` (its CA list / verify mode) and the Host
header can still route the request to a stricter vhost whose client-cert policy is then
only re-read from the default server's handshake result. Reproduced over HTTP/1 and
HTTP/2; HTTP/3 shares the gate.

---

## Part 1 — Variant analysis

General pattern: **post-handshake, per-server TLS policy is read from the Host-routed
server while the handshake actually ran under the negotiated/default server.** The
"server whose SSL_CTX was used" is recorded faithfully in `hc->conf_ctx`
(`ngx_http_request.c:309` default server at init; updated to the matched SNI server at
`ngx_http_request.c:972`). The gate wrongly keys off `hc->ssl_servername` (presence of a
*matched SNI*) instead of off "routed server != `hc->conf_ctx`".

### 1a. Every per-server SSL setting consulted after routing

All in `ngx_http_process_request()` (`src/http/ngx_http_request.c:2147-2193`), reached
after `ngx_http_set_virtual_server()` has re-homed `r` to the Host-selected vhost, and in
the `$ssl_*` variables:

| State | Where consulted after routing | Handshake-bound value read | Mismatch matters? | Verdict |
|---|---|---|---|---|
| `ssl_verify_client` level (`sscf->verify`) | `ngx_http_request.c:2147,2149,2166` | — (uses routed `sscf->verify` to decide whether to re-check) | the *level* is the routed server's, but the *result* it gates on is the negotiated server's | **Defect-same-root-cause** |
| handshake verify result | `SSL_get_verify_result()` `:2150` | computed under negotiated server's CA list / `verify_depth` | yes — a cert valid under the default CA passes for the routed CA | **Defect-same-root-cause** |
| required peer cert | `SSL_get_peer_certificate()` `:2167` | cert requested by negotiated server's `CertificateRequest` | yes — if default requests certs, routed `verify on` is satisfied by a foreign cert | **Defect-same-root-cause** |
| `ssl_client_certificate` / `ssl_trusted_certificate` (the CA set) | set on the negotiated `SSL_CTX` only (`ngx_http_ssl_module.c:849-880`); never re-consulted post-handshake | routed server's CA never applied | yes — this is the crux of the bypass | **Defect-same-root-cause** |
| `ssl_verify_depth` | folded into the negotiated `SSL_CTX` (`:863,872`) | negotiated depth used | yes (same mechanism); lower risk | **Defect-same-root-cause** |
| `ssl_crl` | loaded into the negotiated `SSL_CTX` store (`ngx_ssl_crl`), applied during handshake | negotiated CRL used | yes — routed server's CRL not enforced | **Defect-same-root-cause** |
| `ssl_ocsp` / `ssl_ocsp_responder` / `ssl_ocsp_cache` | `ngx_ssl_ocsp_get_status()` `:2183`; validation kicked off at handshake (`ngx_event_openssl.c:2214,2267,2423`) | OCSP validated against negotiated server's responder/chain | yes — routed server's OCSP policy not enforced | **Defect-same-root-cause** |
| `$ssl_client_verify`, `$ssl_client_cert`, `$ssl_client_s_dn`, … | `ngx_ssl_get_client_verify` etc. read `c->ssl->connection` (`ngx_event_openssl.c:6561,6569`) | reflect the negotiated handshake | yes, for apps that trust these downstream (auth_request, proxy_set_header) — but this is pre-existing and identical for the SNI-present case too | **Consistent** (connection-level by design; see TLS-G-1) |
| `ssl_early_data` | consumed during handshake under negotiated `SSL_CTX`; no post-routing per-server re-read | n/a | no additional gap beyond the above | **Consistent** |
| `ssl_reject_handshake` | applied in `ngx_http_ssl_servername()` `done:` `:1020-1026` on `hc->conf_ctx` (handshake server) — before any HTTP | n/a (rejects at TLS) | no; it is in fact the designed mitigation | **Consistent** (mitigation) |

All the "Defect-same-root-cause" rows are **facets of TLS-1, not independent bugs**: a
single gate fix that rejects the request before `ngx_http_process_request()` closes every
one of them at once, because none of these post-handshake reads are reached.

### 1b. Stream and mail

- **Stream** (`src/stream/ngx_stream_ssl_module.c`): virtual-server selection happens
  *inside* the SNI callback `ngx_stream_ssl_servername()` (`:574`, `ngx_stream_find_virtual_server` `:641`, `SSL_set_SSL_CTX`/`SSL_set_verify` `:665-670`). The verify
  re-check in `ngx_stream_ssl_handler()` reads `sscf` from the session's selected server
  (`:450`, checks at `:465-500`). There is **no Host-layer re-route after the handshake**
  (stream has no application host header that changes the server), so negotiated server ==
  verify server. No SNI => default server governs and *stays*. **Verdict: Consistent** —
  no equivalent gap. (`ssl_preread` in the *stream proxy* only populates variables; it does
  not re-select the server's verify policy.)
- **Mail** (`src/mail/ngx_mail_handler.c:399,423`): no `tlsext_servername` callback is
  registered in `ngx_mail_ssl_module.c` (grep: none), so there is no SNI-based virtual
  server switch and no post-handshake re-route; verify runs on the single listen server.
  **Verdict: Not applicable.**

### 1c. HTTP/3 / QUIC

- Each H3 request stream copies `ssl_servername`, `ssl_servername_regex` and `conf_ctx`
  from the QUIC parent connection (`src/http/v3/ngx_http_v3_request.c:81-88`), and routes
  `:authority` through the **same** `ngx_http_set_virtual_server()`
  (`ngx_http_v3_request.c:987`). So the gate is identical to h1/h2 — **the same fix covers
  H3**.
- QUIC/TLS1.3 still invokes `ngx_http_ssl_servername()`; a **no-SNI QUIC connection is
  accepted** (it reaches `done:` and is admitted unless `ssl_reject_handshake`), so the
  *no-SNI* variant is theoretically reachable over H3, and the *unmatched-SNI* variant is
  the realistic one (real QUIC clients always send SNI). **Verdict: Defect-same-root-cause**
  (confirmed by code trace; not executed — no HTTP/3 client available here).

### 1d. Regex-SNI and "SNI matched the default server" cases

- **Regex SNI** (`hc->ssl_servername_regex`): only set when an SNI matched (so
  `hc->ssl_servername != NULL`). It is handled inside the existing SNI branch — on Host==SNI
  the regex is re-executed (`ngx_http_request.c:2496-2503`); on Host!=SNI the existing 421
  guard applies. **Verdict: Consistent** (already covered; untouched by the fix).
- **SNI matched server is the default server**: `hc->ssl_servername` is set and
  `hc->conf_ctx` == default ctx. Host==SNI short-circuits OK; Host!=verify-vhost fires the
  existing 421. **Verdict: Consistent** (already covered).

### 1e. New candidate

**TLS-G-1 (Low / design-consistent, not fixed by this patch):** when the routed vhost has
`ssl_verify_client` **off** but its application consumes `$ssl_client_verify` /
`$ssl_client_s_dn` (e.g. `proxy_set_header X-Client-DN $ssl_client_s_dn;` or
`auth_request`), those variables reflect the *negotiated* (default) server's handshake, so
a no-SNI client can present identity minted under the default server's CA and have it
forwarded as if verified by the routed vhost. This is **not introduced by the no-SNI path**:
the same connection-level semantics apply to the SNI-present case, and the existing 421
guard likewise only fires on `sscf->verify`. It is therefore reported as a low-priority,
design-consistent note rather than a defect; the verify-gated fix below (which matches
upstream's existing choice to gate on `sscf->verify`) deliberately does not change it. An
operator relying on those variables on a non-verifying vhost should set
`ssl_reject_handshake` or a dedicated listener. Evidence:
`ngx_event_openssl.c:6555-6575` (`$ssl_client_verify` reads `c->ssl->connection`).

---

## Part 2 — Remediation

### Patch (full diff also at `audit/patches/TLS-1.diff`)

```diff
--- a/src/http/ngx_http_request.c
+++ b/src/http/ngx_http_request.c
@@ -2535,6 +2535,34 @@
             ngx_http_finalize_request(r, NGX_HTTP_MISDIRECTED_REQUEST);
             return NGX_ERROR;
         }
+
+    } else if (hc->ssl && rc == NGX_OK && cscf->ctx != hc->conf_ctx) {
+
+        /*
+         * The client did not use TLS SNI (or used an SNI that matched no
+         * virtual server), so the handshake - including the client
+         * certificate request, the trusted CA list and the verification
+         * result - was performed under hc->conf_ctx (the listen's default
+         * server).  The Host header has now routed the request to a
+         * different virtual server.  If that server enforces client
+         * certificate verification, its policy was never applied during
+         * the handshake, so reject the request the same way a mismatching
+         * SNI is rejected, instead of admitting it on the default server's
+         * verification result.
+         */
+
+        ngx_http_ssl_srv_conf_t  *sscf;
+
+        sscf = ngx_http_get_module_srv_conf(cscf->ctx, ngx_http_ssl_module);
+
+        if (sscf->verify) {
+            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
+                          "client attempted to request the server name "
+                          "different from the one that was negotiated "
+                          "without using TLS SNI");
+            ngx_http_finalize_request(r, NGX_HTTP_MISDIRECTED_REQUEST);
+            return NGX_ERROR;
+        }
     }
 
 #endif
```

The new branch sits immediately after the existing `if (hc->ssl_servername)` block in
`ngx_http_set_virtual_server()` and funnels h1/h2/h3 alike (all three call this function:
`ngx_http_request.c:1197/1208/1907/2029`, `v2/ngx_http_v2.c:3600`,
`v3/ngx_http_v3_request.c:987`).

### Why it addresses the root cause

The root cause is that the mismatch gate keyed on *"was a matched SNI present"*
(`hc->ssl_servername`) rather than on *"did the handshake run under a different server
than the one we routed to"*. `hc->conf_ctx` is exactly "the server whose `SSL_CTX`
performed the handshake" — it is the default server at `ngx_http_request.c:309` and is
reassigned to the matched SNI server (together with `SSL_set_SSL_CTX`/`SSL_set_verify`) at
`ngx_http_request.c:972-995`. The new branch handles precisely the case the old gate
missed: SNI absent/unmatched (`hc->ssl_servername == NULL`) and the Host-routed server
`cscf->ctx` differs from `hc->conf_ctx`. When that routed server enforces verification
(`sscf->verify != 0`, i.e. `on`/`optional`/`optional_no_ca`, matching the existing guard),
the request is rejected with 421 *before* `ngx_http_process_request()` reads any
handshake-bound verify result — closing every "Defect-same-root-cause" facet from Part 1
in one place.

### Correctness / compatibility reasoning

- **Default-server-is-the-target still works with no SNI**: when Host routes back to the
  handshake server, `cscf->ctx == hc->conf_ctx`, the branch is skipped (verified: S1
  noSNI/Host=a -> 200).
- **Servers without verify are unaffected**: `sscf->verify == 0` on the routed server =>
  no 421; plain no-SNI vhosting is untouched.
- **Plain HTTP unaffected**: the branch is gated on `hc->ssl` (`ngx_http_request.c:341`
  for h1/h2, `:67` for h3), so a cleartext request routed to a vhost that merely *declares*
  `ssl_verify_client` is never 421'd.
- **SNI-present behaviour is byte-for-byte unchanged**: the existing
  `if (hc->ssl_servername)` block is not modified; the new code is a disjoint `else if`.
  HTTP/2 connection coalescing (SNI=a, `:authority`=b) still takes the SNI branch and
  still returns 421 (verified: H2 SNI=a -> 421 on both binaries).
- **`ssl_reject_handshake` interplay**: with reject_handshake on the default server the
  no-SNI/unknown-SNI handshake is already failed at the TLS layer in
  `ngx_http_ssl_servername()` `:1022-1026`, so the HTTP branch is never reached — no
  interaction.
- **`rc == NGX_DECLINED` (Host matches no vhost)**: the branch requires `rc == NGX_OK`, so
  an unknown Host still falls through to the default server unchanged (safe: verify then
  runs against the same server that handshook).

### Compatibility impact (who legitimately loses)

Only **no-SNI (or unmatched-SNI) clients whose Host routes to a verify-protected
*non-default* vhost on a shared listener**. Those clients were **already in a
mis-verified state** — their request was being admitted against the wrong CA — so this
turns a silent auth bypass into an explicit 421. The denial *code* for one adjacent case
also shifts: a no-SNI request to a protected vhost that previously got 400 ("no required
certificate", from `ngx_http_process_request`) now gets 421 at routing. Both are denials;
421 is the more accurate response. Legitimate clients of such a vhost must send SNI (every
modern browser/curl does) or use a dedicated listener.

### Performance

Nil. One pointer comparison (`cscf->ctx != hc->conf_ctx`) and, only when it holds, one
`ngx_http_get_module_srv_conf` lookup, on the already-slow request-routing path. No new
allocation, no crypto, no syscalls.

### Build + live verification (ASan/UBSan, OpenSSL 3.0.13)

Patched copy configured with the exact options from `configure.log` (prefix/builddir
redirected into the scratch dir) and built clean (`make exit: 0`). Driver:
`audit/patches/TLS-1-regression.sh <binary>` (openssl s_client matrix, config
`audit/gh-tls1/run/nginx.conf`). Real outputs:

```
UNPATCHED  /scratchpad/build-asan/nginx
  FAIL S1 noSNI clientA Host=b        -> HTTP/1.1 200 OK      (BYPASS)
  FAIL S1 unmatchedSNI clientA Host=b -> HTTP/1.1 200 OK      (BYPASS)
  FAIL S2 noSNI clientA Host=b        -> HTTP/1.1 200 OK      (BYPASS)
  PASS S1 noSNI clientA Host=a        -> HTTP/1.1 200 OK
  PASS S1 SNI=a  clientA Host=b       -> HTTP/1.1 421 Misdirected Request
  PASS S1 SNI=b  clientB Host=b       -> HTTP/1.1 200 OK
  PASS S1 noSNI noCert Host=b         -> HTTP/1.1 400 Bad Request (denied)
  PASS S4 noSNI clientB Host=b        -> HTTP/1.1 400 Bad Request (denied)
  PASS S4 SNI=b  clientB Host=b       -> HTTP/1.1 200 OK
  sanitizer-hits: 0   RESULT: HAS-FAIL

PATCHED    /scratchpad/audit/gh-tls1/build-patched/nginx
  PASS S1 noSNI clientA Host=b        -> HTTP/1.1 421 Misdirected Request  (FLIP 200->421)
  PASS S1 unmatchedSNI clientA Host=b -> HTTP/1.1 421 Misdirected Request  (FLIP 200->421)
  PASS S2 noSNI clientA Host=b        -> HTTP/1.1 421 Misdirected Request  (FLIP 200->421)
  PASS S1 noSNI clientA Host=a        -> HTTP/1.1 200 OK
  PASS S1 SNI=a  clientA Host=b       -> HTTP/1.1 421 Misdirected Request
  PASS S1 SNI=b  clientB Host=b       -> HTTP/1.1 200 OK
  PASS S1 noSNI noCert Host=b         -> HTTP/1.1 421 Misdirected Request (denied)
  PASS S4 noSNI clientB Host=b        -> HTTP/1.1 421 Misdirected Request (denied)
  PASS S4 SNI=b  clientB Host=b       -> HTTP/1.1 200 OK
  sanitizer-hits: 0   RESULT: ALL-PASS
```

HTTP/2 (curl 8.5.0/nghttp2), real outputs:

```
                                    UNPATCHED  PATCHED
H2 noSNI clientA :authority=b   ->     200   ->  421   (bypass flipped)
H2 SNI=a  clientA :authority=b  ->     421   ->  421   (coalescing: unchanged)
H2 SNI=b  clientB :authority=b  ->     200   ->  200   (legit: unchanged)
```

No AddressSanitizer / UBSan findings in either run.

---

## Part 3 — Regression test

Two deliverables in `audit/patches/`:

1. **`TLS-1-regression.sh`** (runnable here). Starts a given nginx binary against
   `audit/gh-tls1/run/nginx.conf`, drives the matrix with `openssl s_client`, asserts the
   three no-SNI/unmatched-SNI bypass cases are **421** and the legitimate cases keep
   **200**/existing 421, checks the error log for sanitizer hits, and exits non-zero on any
   failure. **Shown failing on the unpatched binary** (3 bypass assertions = 200) **and
   passing on the patched binary** (all 421/200 as expected) — transcript above.

2. **`TLS-1-regression.t`** (nginx-tests style Perl, modelled on `ssl_verify_client.t` and
   `ssl_reject_handshake.t`). Generates two independent client CAs + a client cert each,
   two vhosts on one TLS listener (default `a.example` verify optional/ca-a;
   `b.example` verify on/ca-b), and asserts no-SNI+ca-a-cert+`Host: b.example` -> 421 plus
   the controls. It declares `has(qw/http http_ssl sni socket_ssl_sni/)`, so like every
   upstream SSL test it **SKIPs cleanly where IO::Socket::SSL is absent** — which is the
   case in this sandbox:
   ```
   TLS-1-regression.t .. skipped: no socket_ssl_sni available
   ```
   It is therefore **designed-but-unrunnable here**; the `.sh` is the runnable equivalent
   and was exercised against both binaries. The `.t` parses and loads `Test::Nginx`
   correctly under `prove` (the skip is the module gate firing, not a syntax error).

### Existing nginx-tests run against the patched binary (regression check)

Runnable (non-SSL) results — no regressions:

```
http_keepalive.t        All tests successful. Result: PASS
h2.t                    All tests successful. Result: PASS
```

SSL-dependent tests skip in this environment (missing IO::Socket::SSL), proven:

```
ssl_verify_client.t     skipped: no socket_ssl_sni available
h2_ssl_verify_client.t  skipped: no socket_ssl_alpn available
ssl_reject_handshake.t  NOTESTS (skip)
ssl_sni.t               NOTESTS (skip)
h2_ssl.t                NOTESTS (skip)
```

So the SSL perl suites could not exercise the patch here; coverage of the patched path is
provided by `TLS-1-regression.sh` (and the `.t` for an environment that has the module).

---

## Summary of verdicts

| Variant | Verdict | Evidence |
|---|---|---|
| post-routing verify result / peer cert / CA / depth / CRL / OCSP (h1/h2) | Defect-same-root-cause (= TLS-1) | `ngx_http_request.c:2147-2193`, module CA setup `:849-880` |
| HTTP/3 `:authority` routing | Defect-same-root-cause | `v3/ngx_http_v3_request.c:81-88,987` |
| stream ssl verify | Consistent (no Host re-route) | `stream/ngx_stream_ssl_module.c:450-500,574-670` |
| mail ssl verify | Not applicable (no SNI switch) | `mail/ngx_mail_handler.c:399-423`; no servername cb |
| regex SNI / SNI==default | Consistent (already covered) | `ngx_http_request.c:2490-2506` |
| `$ssl_client_*` on non-verifying routed vhost | TLS-G-1, Low/design-consistent (not fixed) | `ngx_event_openssl.c:6555-6575` |

Fix: one disjoint `else if` in `ngx_http_set_virtual_server()` keying on
`cscf->ctx != hc->conf_ctx` + `sscf->verify`, gated on `hc->ssl`. Builds clean under
ASan/UBSan; closes the h1/h2/h3 bypass (200->421) with no change to SNI-present behaviour,
legitimate traffic, plain HTTP, or performance.

### Artifacts
- Report: `audit/GH-TLS-1.md`
- Patch: `audit/patches/TLS-1.diff`
- Tests: `audit/patches/TLS-1-regression.sh` (runnable), `audit/patches/TLS-1-regression.t` (skips w/o IO::Socket::SSL)
- Patched build: `audit/gh-tls1/build-patched/nginx`; config `audit/gh-tls1/run/nginx.conf`
