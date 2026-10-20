# NGINX Security Audit: Blue Team Multi-Agent Investigation

Date: 2026-10-20
Repository: https://github.com/nginx/nginx (audited via the fork https://github.com/Ivole32/nginx-fork)
Revision: `b38c9d8068ab55504aa4311f729803b503579520` ("HTTP/3: avoid unaligned stores in Huffman encoding", 2026-10-01), version string 1.31.8 (development)

## 1. Executive summary

The audited tree is byte-for-byte stock nginx at commit b38c9d80. The same commit hash was fetched from `nginx/nginx` and matched, so every conclusion below applies to upstream nginx at that revision, not only to the fork.

No memory-safety vulnerability (out-of-bounds access, integer overflow in length math, use-after-free, double free, uninitialized use) was found by any of the five discovery agents, and a full run of the official nginx-tests suite (5368 tests) against an AddressSanitizer plus UndefinedBehaviorSanitizer build produced no sanitizer report. No HTTP request-smuggling or front-end/back-end desynchronization path was found.

The audit produced one hardening-grade authentication finding and three design-level findings, all independently validated, reproduced on a local sanitizer build, and accompanied by locally tested patches and regression tests. None is a classic exploitable bug; all are gaps where nginx's documented behaviour is weaker than an operator would reasonably expect:

- **TLS-1 (Medium, hardening).** When a TLS client omits SNI, or sends an SNI that matches no server, the handshake runs under the listen's default server, yet the `Host` header can route the request to another virtual host. That host's `ssl_verify_client` policy is only re-checked against the default server's verification result, so a client holding a certificate trusted by the default server is admitted to a vhost that trusts a different CA. The existing "421 Misdirected Request" guard applies only when SNI was sent. Reproduced over HTTP/1 and HTTP/2. A 30-line fix extends the guard to the no-SNI case and was verified to flip the bypass cases from 200 to 421 without changing any legitimate case.
- **CFG-1 (Medium on multi-user hosts, Low otherwise).** The opt-in Control API (`--with-control-api`, `nginx -l addr`) accepts any bind address, performs no authentication or peer check, and serves a verbatim dump of every configuration file and an unauthenticated reload executed in the root master. The man page shows TCP loopback examples with no warning, and there is no audit trail. Reproduced as an unprivileged local user. Proposed hardening: man-page security paragraph, per-request audit log line with peer credentials, and a warning on non-loopback binds. The official control_api tests still pass on the patched build.
- **HTTP-1 (Low-Medium, hardening).** `tunnel_pass` with no argument defaults to `$host:$request_port`, giving a CONNECT forward proxy with no built-in destination or port restriction, including to loopback and link-local targets. This is intended behaviour (the official test suite tunnels to 127.0.0.1) and `allow/deny` or `auth_basic` work, but there is no AllowCONNECT or Safe_ports equivalent. Deny-lists on `$host` are shown to be bypassable; only allow-lists are safe. A config-time warning for `tunnel_pass` placed in a location that CONNECT can never reach was implemented and tested, and a reference allow-list configuration was verified.
- **MEM-1 (Low, API contract).** In the new JSON parser, a consumer that returns `NGX_JSON_SKIP` on a scalar array element never receives the matching `ARRAY_CLOSE` event. No in-tree consumer uses scalar skips, so there is no reachable impact today. A 16-line fix was fuzzed for one million parses per seed under sanitizers.

Four further low or informational items were found during validation and variant analysis (an undefined-behaviour nit in zero-length copies, a CONNECT with port 0 answering 500 instead of 400, a HTAB/C0 forwarding interoperability gap, and a missing bounds check on a worker-to-worker channel message). Two hypotheses raised by discovery agents were rejected after validation.

All fixes are **proposed and locally tested** patches under `audit-deliverables/patches/`. Nothing was committed, no upstream file was modified, and no fix has been submitted or merged upstream.

## 2. Scope and revision

- Checked-out revision: `b38c9d8068ab55504aa4311f729803b503579520` on `master`, 50 commits of visible history (shallow fork). Identity with upstream confirmed by `git fetch --depth 1 https://github.com/nginx/nginx.git b38c9d80...`, which returned the same object.
- Source size: 268 C files, about 241k lines under `src/`.
- In scope: HTTP/1, HTTP/2, HTTP/3 and QUIC, upstream modules (proxy, proxy_v2, grpc, fastcgi, scgi, uwsgi, tunnel), request and body handling, URI normalization, core data structures and string helpers, resolver, file cache, event pipe, configuration parsing and cycle management, process model and privilege separation, access control modules, TLS integration (OpenSSL 3.0.13 as built), session cache and tickets, OCSP, QUIC crypto, stream and mail modules, the new JSON parser and renderer, the Control API, Priority header parsing, upstream sticky and zone modules, GeoIP MMDB path.
- Out of scope or not reached: see Section 11.

## 3. Methodology and tooling

- **Agents.** Coordinator (this session) plus discovery agents B (HTTP/protocol), C (memory safety), D (configuration/access control), E (TLS/crypto) and B2 (QUIC transport, mail, stream, resource exhaustion). Four independent validation agents (F) each received one candidate group with the explicit mandate to disprove it. Four combined variant-analysis and remediation agents (G+H) handled the validated findings. All agents worked from a shared brief that forbade repository modification and non-loopback testing. Every hand-off used the fixed Task ID / Parent / Objective / Scope / Evidence / Deliverables / Constraints format.
- **Static analysis.** Line-by-line reading of the files listed per agent, with control-flow and data-flow tracing from untrusted input to the suspected operation. Agents were required to cite file and line and to look for existing mitigations.
- **Dynamic analysis.** A private build (`--with-debug`, HTTP/2, HTTP/3, stream, mail, DAV and other modules) compiled with `-fsanitize=address,undefined` under gcc 13.3. The official nginx-tests suite (shallow clone of 2026-10-20) was run against it: 511 files, 5368 tests, no ASan or UBSan output. Failures were limited to IPv6-dependent tests (the container has no IPv6) and SSL tests skipped for lack of `IO::Socket::SSL`. Candidates were reproduced on this build or on separately built copies (Control API build, patched builds) using `openssl s_client`, `curl`, raw sockets, and standalone harnesses for the JSON parser.
- **Coordinator verification.** For every finding the coordinator re-read the cited code and re-ran at least one reproduction or regression artifact personally: the JSON skip reproducer and both regression binaries, the TLS-1 regression script on both binaries, the CFG-1 and HTTP-1 regression tests on both binaries, and the `CONNECT host:0` probe.
- **Documentation and intent.** In-repo `docs/` (man page, changelog XML), `SECURITY.md`, and the official test suite were consulted to distinguish design decisions from defects.

## 4. Findings summary

| ID | Severity | Component | Confidence | Status |
|----|----------|-----------|------------|--------|
| TLS-1 | Medium (hardening) | HTTP virtual-server routing vs TLS client verification (`ngx_http_request.c`) | High | Confirmed behaviour, known design limitation; fix proposed and locally tested |
| CFG-1 | Medium (multi-user host) / Low (isolated host) | Control API (`ngx_control.c`, `nginx -l`) | High | Confirmed behaviour, design decision; hardening and docs proposed and locally tested |
| HTTP-1 | Low-Medium (hardening) | Tunnel module (`ngx_http_tunnel_module.c`) | High | Confirmed behaviour, design decision; warning implemented, reference config verified |
| MEM-1 | Low (API contract, unreachable in tree) | JSON parser (`ngx_json_parse.c`) | High | Confirmed; fix proposed and locally tested |
| HTTP-F-1 | Low | Tunnel module config footgun | High | Confirmed; config-time warning implemented |
| HTTP-G-1 | Low | CONNECT with port 0 returns 500 | High | Confirmed by coordinator; fix proposed, not patched |
| HTTP-3 | Low | h1 to h2 header value forwarding (`proxy_v2`, `grpc`) | High | Validated as interoperability gap, not a security defect |
| CFG-F-1 | Informational | `ngx_memcpy(dst, NULL, 0)` via empty build string | High | Confirmed; one-line fix proposed |
| HTTP-G-2 | Informational | Same zero-length copy class in tunnel error logging | Medium | Candidate |
| CFG-G-1 | Low | Worker channel `slot` not bounds-checked | Medium | Candidate (senders are same-uid workers) |
| TLS-G-1 | Low | `$ssl_client_*` variables reflect negotiated server on non-verifying vhost | Medium | Candidate, design-consistent |
| HTTP-2 | Informational | Server-wide `allow_connect` reaches non-tunnel handlers | High | Rejected as security issue (mechanism confirmed, no byte pipe) |
| DOS-1 | Informational | QUIC out-of-order buffer granularity | High | Rejected as vulnerability (bounded by flow control) |

Severity follows the realistic impact after validation. CVSS 4.0 vectors are given only where a validator could defend one (TLS-1).

## 5. Confirmed findings

### Finding: Client-certificate policy of a Host-selected virtual host is not enforced when the client omits SNI

- **ID:** TLS-1
- **Status:** Confirmed behaviour; classified as a known design limitation with a recommended code hardening. Remediation proposed and locally tested.
- **Severity:** Medium (hardening). Validator's CVSS 4.0 vector if treated as a vulnerability: `AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` (attacker must hold a certificate the default server trusts, and the operator must co-host differently-verified vhosts on one listener).
- **Confidence:** High. Reproduced independently by the discovering agent, the validator, and the remediation agent; the coordinator re-ran the regression matrix.
- **Affected files:** `src/http/ngx_http_request.c`: `ngx_http_ssl_servername()` (hc->ssl_servername set only on a matched SNI), `ngx_http_set_virtual_server()` (both guard blocks gated on `hc->ssl_servername`, lines 2490 and 2521), `ngx_http_process_request()` (lines 2147-2192, re-check using `SSL_get_verify_result` and `SSL_get_peer_certificate` of the already-completed handshake). HTTP/2 and HTTP/3 funnel `:authority` through the same function.
- **Code location:** 

```c
    if (hc->ssl_servername) {
        ...
        if (sscf->verify) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client attempted to request the server name "
                          "different from the one that was negotiated");
            ngx_http_finalize_request(r, NGX_HTTP_MISDIRECTED_REQUEST);
            return NGX_ERROR;
        }
    }
```

- **Root cause:** Post-handshake per-server TLS policy (verify mode, CA list, depth, CRL, OCSP) is read from the Host-routed server, while the handshake, including the CertificateRequest and the trust anchor, ran under the negotiated server, which is the listen default when SNI is absent or unmatched. The mismatch guard that exists for the SNI case does not cover that state.
- **Attack preconditions:** Two or more `server` blocks on one listen address. The default or fallback server requests client certificates and trusts a CA the attacker can satisfy. The target server has `ssl_verify_client on` with a different `ssl_client_certificate`. Attacker connects without SNI (or with an unknown SNI) and sends `Host:` for the target. Works over HTTP/1.x and HTTP/2.
- **Technical evidence:** With server A (default, `ssl_verify_client optional`, CA_A) and server B (`ssl_verify_client on`, CA_B): no SNI plus a CA_A client certificate plus `Host: b.example` returned `200` from B. Control cases: SNI `a.example` plus `Host: b.example` returned `421`; SNI `b.example` with a CA_A certificate returned `400`; no certificate returned `400`. Same with both servers set to `on` and different CAs.
- **Validation results:** Independent reproduction on the sanitizer build over HTTP/1.0 and HTTP/2 (`curl --http2`), ASan clean. Fully mitigated by `ssl_reject_handshake on` in the default server, by a default server that does not request client certificates, or by a dedicated listen address.
- **Independent review:** Validator classified it as a known limitation rather than a broken check: the 1.11.0 changelog scopes the 421 response to "a virtual server different from one negotiated", `ssl_reject_handshake.t` tests that the default server governs the no-SNI case, and `ssl_sni.t` carries a TODO acknowledging Host/SNI mismatch is unrestricted. The validator still recommended the code hardening.
- **Variant analysis:** One root cause covers every post-routing consumer (verify result, peer cert requirement, CA set, verify depth, CRL, OCSP). HTTP/3 shares the gate. Stream is consistent (server chosen inside the SNI callback, no later re-routing). Mail not applicable. Regex SNI and SNI equal to default are already covered. TLS-G-1 noted separately.
- **Security impact:** Authentication bypass of a client-certificate-protected vhost under the stated co-hosting precondition. No confidentiality impact on the default server. No availability impact.
- **Remediation:** `audit-deliverables/patches/TLS-1.diff` adds an `else if (hc->ssl && rc == NGX_OK && cscf->ctx != hc->conf_ctx)` branch after the existing SNI guard in `ngx_http_set_virtual_server()`: when the routed server is not the one whose `SSL_CTX` performed the handshake and that routed server has `ssl_verify_client` enabled, respond 421 exactly as the SNI-mismatch case does. SNI-present behaviour is unchanged, plain HTTP is untouched, non-verifying vhosts are unaffected, and the only clients that change outcome are no-SNI clients of a verify-protected non-default vhost, who were previously admitted under the wrong policy. Compatibility note: those clients now receive 421 and must send SNI. Performance impact is one pointer comparison per request.
- **Regression tests:** `TLS-1-regression.sh` (runnable; drives `openssl s_client`) fails on the unpatched binary with three bypass cases returning 200 and passes all nine cases on the patched binary. `TLS-1-regression.t` is an nginx-tests style test modelled on `ssl_verify_client.t`, designed but unrunnable here because `IO::Socket::SSL` is absent. Existing `http_keepalive.t` and `h2.t` pass on the patched build.
- **Open questions:** Whether upstream prefers the 421 hardening or a documentation-only stance; whether to also warn at configuration time when a listener mixes verify policies without `ssl_reject_handshake`.
- **Agent history:** E discovered and reproduced; F (VAL-TLS-1) validated and reclassified; G+H (GH-TLS-1) variant analysis, patch, regression; coordinator re-ran the regression matrix on both binaries.

### Finding: Control API has no authentication, no peer check, and no audit trail

- **ID:** CFG-1
- **Status:** Confirmed behaviour; design decision that needs hardening and documentation. Remediation proposed and locally tested.
- **Severity:** Medium on hosts with untrusted local accounts or when bound to a non-loopback address; Low on single-tenant hosts using a unix socket.
- **Confidence:** High.
- **Affected files:** `src/os/unix/ngx_control.c`: `ngx_control_init()` (any `ngx_parse_url` listen address accepted; unix socket chmod 0600 before `listen()`), `ngx_control_handle_accept()` (`accept(fd, NULL, NULL)`, no peer capture), `ngx_control_content()` (`GET /1/control/config` returns every parsed configuration file verbatim; `PATCH /1/control/config` calls `ngx_init_cycle()` in the master and respawns workers), `src/core/nginx.c` (`-l` option), `src/core/ngx_conf_file.c:222-233` (config dump forced on when the API is enabled), `docs/man/nginx.8` "CONTROL SOCKET" section.
- **Root cause:** Reachability is the only authorization. The endpoint is a plain HTTP/1.x protocol served by the root master process, with no credential, token, `SO_PEERCRED`, or source-address check, and no log line naming the requester.
- **Attack preconditions:** Built with `--with-control-api` (off by default, new in 1.31.5), started with `-l <tcp addr>` in master mode. Any process able to `connect()`: every local account for `127.0.0.1:port`; any remote host for a non-loopback bind.
- **Technical evidence:** As uid 65534 against a root master on `127.0.0.1:18700`: `GET /1/control/config` returned the full `nginx.conf` and an included file containing a marker secret; `PATCH /1/control/config` returned `200 {"logs":[]}` and the worker pid changed. Unix socket mode is `srw------- root` and uid 65534 gets `EACCES`.
- **Validation results:** Independent reproduction with a separate build. Parser probing (oversize lines, control bytes, path tricks, 70 idle connections) produced only 200/400/404 or connection close with no sanitizer output; the official `control_api.t` (98 tests) and `control_api_unix.t` (8 tests) pass. No code-execution or memory-corruption path was found. The request parser is bounded at 1024 bytes and the 64-fd cap evicts the oldest connection.
- **Independent review:** Validator confirmed every factual claim and re-scoped from "vulnerability" to "design decision needing hardening": the man page documents TCP loopback binds with no warning, official tests bind TCP and treat 0600 as the only access control, and `SECURITY.md` treats the control plane as trusted. Comparable to HAProxy stats socket, Envoy admin and `stub_status`, all of which rely on bind scope; unlike those, this one serves full configuration text and a reload from the root process.
- **Variant analysis:** No real variant. The master accepts only on the control socket; the worker channel has a single reader registered only in workers, so a compromised worker cannot command the master; the `NGINX_CTRL` environment hand-off is consumed only when `-l` is also given and follows the same trust model as `NGINX=` listen-fd inheritance; configuration dumps for `-T`, `-l` and debug builds live in the cycle pool and add no new boundary; `stub_status` is opt-in and behind the HTTP access phase. CFG-G-1 (Low) noted: `ngx_channel_handler` stores `ch.slot` without a bounds check, but only same-uid sibling workers can send.
- **Security impact:** Confidentiality: disclosure of all configuration text, including embedded upstream credentials, secure-link secrets, file paths and topology. Integrity/availability: unauthenticated forced reload with worker respawn and connection draining at an attacker-chosen moment, and reload error lines returned to the caller. No privilege escalation found.
- **Remediation:** `audit-deliverables/patches/CFG-1.diff`: (1) man-page security paragraph stating the socket is unauthenticated and recommending a unix socket or loopback with host firewalling; (2) peer capture in `accept()` with `SO_PEERCRED` on unix sockets and one NOTICE-level audit line per response of the form `control: client unix uid:0 gid:0 pid:N, "PATCH /1/control/config" 200`; (3) a startup warning when the TCP bind address is not loopback. Actual authorization (token or peer-uid allow-list) is left as a documented proposal because it changes the protocol. The path is logged only after parser acceptance, so no log injection. Performance: one `getsockopt` and one log line per control connection.
- **Regression tests:** `CFG-1-regression.t`: on the unpatched build the seven audit and warning subtests fail; on the patched build all 16 pass. `control_api.t` and `control_api_unix.t` pass 106/106 on the patched build. The non-loopback case binds to a TEST-NET address so nothing reachable is opened.
- **Open questions:** Whether the non-loopback warning should become an error with an explicit override upstream; audit lines require `error_log` at notice level or lower to be visible.
- **Agent history:** D discovered and reproduced; F (VAL-CFG-1) validated, re-scoped, and found CFG-F-1; G+H (GH-CFG-1) variant analysis, patches, regression; coordinator checked the man page and SECURITY.md and re-ran the regression test on both builds.

### Finding: `tunnel_pass` defaults to a client-controlled CONNECT target with no destination or port restriction

- **ID:** HTTP-1 (merges HTTP-F-2; HTTP-F-1 handled together)
- **Status:** Confirmed behaviour; design decision. Hardening warning implemented and tested; reference allow-list configuration verified; documentation recommended.
- **Severity:** Low-Medium (hardening). Once enabled without access control it is an open CONNECT proxy into loopback, link-local and private ranges.
- **Confidence:** High.
- **Affected files:** `src/http/modules/ngx_http_tunnel_module.c`: `ngx_http_tunnel_pass()` lines 463-474 (`cscf->allow_connect = 1` server-wide; zero-argument form sets `$host:$request_port`), `ngx_http_tunnel_eval()` 225-268 (`ngx_parse_url` with `no_resolve`), `ngx_http_tunnel_handler()`; `src/http/ngx_http_parse.c` 737-740 (CONNECT URI pinned to "/"); `src/http/ngx_http_request.c` 1188-1206 and 2098-2111.
- **Code location:**

```c
    if (cf->args->nelts == 1) {
        ngx_str_set(&url, "$host:$request_port");
    } else {
        url = value[1];
    }
```

- **Root cause:** The module ships no equivalent of Apache `AllowCONNECT` or Squid `Safe_ports`; the only restriction mechanisms are generic access-phase handlers that the operator must remember to add. Separately, because CONNECT always carries URI "/", a `tunnel_pass` in any other location is unreachable while `allow_connect` is still enabled for the whole server (HTTP-F-1).
- **Attack preconditions:** `tunnel_pass;` (or an explicit `$host:$request_port`) in the location matching "/", reachable over HTTP/1.1, with no `allow/deny`, `auth_basic` or variable-based restriction.
- **Technical evidence:** A bidirectional tunnel to a client-chosen `127.0.0.1:18850` was established through the sanitizer build and bytes flowed both ways. `deny all` gave 403 and `auth_basic` gave 407 then 200 with credentials. A fixed `tunnel_pass host:port` ignores the client authority. The CONNECT authority always wins over a differing `Host` header. Userinfo, `%`, scheme and `unix:` forms are rejected at the request line; IPv6 literals including `[::ffff:127.0.0.1]`, `LOCALHOST.` (normalised to `localhost`) and shorthand IP forms are accepted, so a `$host` deny-list is bypassable and only an allow-list is safe.
- **Validation results:** Reproduced; official `tunnel.t` tunnels to 127.0.0.1 as a passing case, and `tunnel_auth_basic.t` demonstrates the "closed proxy" form. No in-repo module documentation exists for `tunnel_pass`.
- **Independent review:** Validator: confirmed behaviour, intended forward proxy, real gap versus other proxies' default port restrictions; severity Low-Medium.
- **Variant analysis:** No other directive in the tree defaults to a request-controlled destination; `*_pass` with variables are operator opt-in through the same `ngx_parse_url` path; mail takes the backend from the trusted auth server with a port range check; resolver name encoding is bounded. New: HTTP-G-1 and HTTP-G-2 (below).
- **Security impact:** Server-side request forgery and open-proxy abuse from an Internet-facing listener when the module is enabled without access control. No memory-safety impact.
- **Remediation:** `audit-deliverables/patches/HTTP-1.diff` adds `ngx_http_tunnel_check_location()`, a configuration-time `[warn]` when `tunnel_pass` sits in a location that CONNECT's pinned URI "/" can never match (exact or prefix locations other than "/", regexes that do not match "/"; server level, named and predicate locations are skipped). A second warning for "default target without access control" was evaluated and rejected because it would require inspecting private structures of optional modules and would produce false warnings. Instead a reference hardening configuration is documented and verified: a `map` on `"$host:$request_port"` producing `$tunnel_allowed` with `default 0` and an allow-list entry such as `"~^allowed\.example:443$" 1`, followed by `if ($tunnel_allowed = 0) { return 403; }` before `tunnel_pass;`. A `tunnel_allow_ports` directive was sketched but not implemented because port limits alone still allow `127.0.0.1:443`, and a host allow-list needs a post-resolution hook the upstream API does not provide. Recommendation for upstream: document the security model and the allow-list pattern, and consider a built-in allow-list directive.
- **Regression tests:** `HTTP-1-regression.t`: on the unpatched build only test 1 (warning for `location = /x { tunnel_pass; }`) fails; on the patched build 13/13 pass. The allow-list part (loopback, `127.0.0.1:443`, `localhost`, `[::1]`, allowed host on another port all 403; allowed host on 443 tunnels) passes on both. Official `tunnel.t`, `tunnel_auth_basic.t`, `tunnel_next_upstream.t` pass 34/34 on both builds.
- **Open questions:** Whether upstream wants a built-in destination allow-list; the warning cannot detect shadowing by another location or an `if` that never holds.
- **Agent history:** B discovered (static); F (VAL-HTTP-1) validated, rejected HTTP-2, raised HTTP-F-1/F-2; G+H (GH-HTTP-1) variant analysis, warning patch, reference config, regression; coordinator re-ran the regression test and the port-0 probe.

### Finding: JSON parser suppresses `ARRAY_CLOSE` after a scalar-element skip

- **ID:** MEM-1
- **Status:** Confirmed; not reachable through any in-tree consumer. Fix proposed and locally tested.
- **Severity:** Low (API contract defect in new code; no memory-safety impact).
- **Confidence:** High.
- **Affected files:** `src/core/ngx_json_parse.c`: `ngx_json_emit()` lines 753-763 (scalar skip sets `skip_until_depth = depth - 1`), `ngx_json_close()` 791-807 (decrements depth, then emits while still skipping), skip-stop test at lines 89-99 (lazy, at loop top). Consumer: `src/http/modules/ngx_http_json_module.c` returns `NGX_JSON_SKIP` only on container OPEN and KEY events.
- **Root cause:** Skip state is cleared lazily at the top of the parse loop instead of at the container boundary, and the two skip origins (container OPEN, which must suppress its own CLOSE, and scalar element, which must not) are indistinguishable at close time.
- **Attack preconditions:** None today. Requires a consumer that returns SKIP on a scalar value inside an array.
- **Technical evidence:** Input `{"a":[1,2],"b":3}` with SKIP on the number 1 delivered `OBJ_OPEN, KEY a, ARR_OPEN, NUM 1, KEY b, NUM 3, OBJ_CLOSE` and no `ARR_CLOSE`. A frame-tracking consumer would pop the wrong frame on later CLOSE events.
- **Validation results:** Coordinator re-ran the reproducer and both regression binaries. The parser was fuzzed with container and key skips for three million parses with no invariant or sanitizer failure, and with scalar skips the invariant failures reproduce on every seed.
- **Independent review:** Coordinator (independent of Agent C) confirmed by code reading and execution.
- **Variant analysis:** 26 traced shapes: 12 same-root-cause defects (every scalar-skip-in-array shape, including nested last element, whitespace before `]`, and end of input), 14 consistent. The chunk-boundary `start == NULL` note is a separate, unreachable class. Grep confirms the HTTP module is the only consumer.
- **Security impact:** None reachable. Future consumers using scalar skips would desynchronize.
- **Remediation:** `audit-deliverables/patches/MEM-1.diff` adds a one-bit `skip_close` to the context, set for scalar-element skips and cleared for OPEN/KEY skips; `ngx_json_close()` clears the skip before emitting the CLOSE when `skip_close` is set and depth has reached the skip depth. Differential tracing of 1.2 million parses with container and key skips is byte-identical before and after, so the HTTP module's behaviour is unchanged. Timing within noise.
- **Regression tests:** `gh-mem1/regress.c` (36 fixed cases): 16 fail on the unpatched parser, 0 on the patched one. Fuzz with scalar skips: five seeds times 500k iterations pass on patched, abort on every seed on unpatched.
- **Open questions:** None.
- **Agent history:** C discovered and reproduced; coordinator validated; G+H (GH-MEM-1) variants, patch, tests.

## 6. Unresolved candidates and rejected hypotheses

- **HTTP-G-1 (Low, confirmed by coordinator):** `CONNECT host:0` returns 500 because `ngx_http_validate_host` only checks the upper port bound, `$request_port` renders empty for 0, and `ngx_parse_url` then fails with "invalid port in upstream". Port 70000 correctly returns 400. Proposed fix: reject `r->port == 0` with 400 in the CONNECT branch of `ngx_http_process_request_header()`. Not patched.
- **CFG-F-1 (Informational, confirmed):** `GET /1/nginx` renders `ngx_control_build` which is `{0, NULL}` when `NGX_BUILD` is undefined, reaching `ngx_memcpy(dst, NULL, 0)` in `ngx_pstrdup`. Technically undefined per C11, harmless in practice. One-line fix in `audit-deliverables/patches/CFG-F-1.diff` (`ngx_string("")`), verified to remove the UBSan line.
- **HTTP-G-2 (Informational, candidate):** The tunnel module is the only upstream module that does not set `u->schema`, so upstream error logging formats a `{0, NULL}` string and triggers the same zero-length copy class under UBSan. Proposed fix: set `u->schema` like other modules.
- **CFG-G-1 (Low, candidate):** `ngx_channel_handler` in workers stores `ch.slot` without bounding it to `NGX_MAX_PROCESSES`. Only same-uid sibling workers can send on the channel, so no boundary is crossed. Optional one-line check.
- **TLS-G-1 (Low, candidate, design-consistent):** `$ssl_client_verify` and `$ssl_client_s_dn` on a non-verifying routed vhost reflect the negotiated (default) handshake. Pre-existing, not changed by the TLS-1 patch.
- **HTTP-3 (Low, validated as interoperability gap):** The HTTP/1 parser trims only SP as whitespace and rejects only NUL, CR and LF in values, so leading or trailing HTAB and bytes such as 0x0B pass through and are HPACK-encoded verbatim by `proxy_v2` and `grpc`. nginx's own HTTP/2 and HTTP/3 inbound validators accept the same set, so nginx is self-consistent; a strict RFC 9113 receiver may reject the request. HPACK is length-prefixed, so no framing or smuggling impact. Long-standing grpc behaviour. Hardening note: trim HTAB as OWS and consider rejecting C0/DEL bytes in the HTTP/2 writer.
- **HTTP-2 (rejected as a security issue):** `allow_connect` is server-wide and CONNECT routes to whatever handles "/", so a `proxy_pass` there forwards `CONNECT / HTTP/1.1` to the backend. Validation showed no byte pipe forms (`u->upgrade` is set only on a 101 with a client Upgrade), no client bytes reach the backend, and the connection closes. Configuration oddity only; the HTTP-1 warning covers the misplacement case.
- **DOS-1 (rejected as a vulnerability):** QUIC out-of-order STREAM and CRYPTO data is stored in 4096-byte buffers, so one byte per 4096-aligned offset costs a full buffer. Bounded by per-stream `recv_max_data` (default 64k for HTTP/3), connection flow control, the `max_frames` cap and the datagram flood check; CRYPTO is capped at 65535 bytes. Informational.

## 7. Independent validation results

| Candidate | Validator verdict | Key evidence |
|-----------|-------------------|--------------|
| TLS-1 | Known limitation, real behaviour, hardening recommended | Independent repro h1 and h2; changelog and test-suite intent; mitigations confirmed |
| CFG-1 | Confirmed facts; design decision needing hardening and docs | Repro as uid 65534; official control_api tests pass; no RCE path; no audit trail |
| HTTP-1 | Confirmed; design decision; no built-in restriction | Full tunnel to loopback; access control works; tunnel.t tunnels to 127.0.0.1 |
| HTTP-2 | Mechanism confirmed; security consequence rejected | Backend received `CONNECT /`; no byte pipe |
| HTTP-3 | Mechanism confirmed; re-scoped to interoperability | HPACK bytes `09 76 09` and `61 0b 62` captured; h2/h3 inbound equally lenient |
| MEM-1 | Confirmed by coordinator | Reproducer and regression binaries re-run |

Every validator was permitted to reject; two did (HTTP-2, and the vulnerability framing of HTTP-3), and two re-scoped (TLS-1, CFG-1).

## 8. Similar-vulnerability analysis and common root causes

- **Post-handshake policy read from the wrong server (TLS-1).** Single root cause behind all post-routing TLS checks in HTTP/1, HTTP/2 and HTTP/3. Stream and mail do not re-route after the handshake. The fix location (`ngx_http_set_virtual_server`) is shared by all three HTTP versions.
- **Reachability as authorization (CFG-1).** Unique to the Control API; worker channel, `NGINX_CTRL` hand-off, configuration dumps and `stub_status` were checked and are consistent with their trust models.
- **Client-controlled default destination (HTTP-1).** No other directive defaults a destination from request data. `$host`-based deny-lists are unsafe because of case, trailing-dot and IPv6-form variants.
- **Lazy skip-state clearing (MEM-1).** Twelve input shapes share the root cause; the single consumer avoids them.
- **Zero-length copies from `{0, NULL}` strings (CFG-F-1, HTTP-G-2).** A small recurring class: nginx's copy macros do not guard `n == 0` with a NULL source. Harmless on all current platforms; worth a defensive guard in the macros or at the two call sites.

## 9. Remediation proposals and regression tests

All patches are in `audit-deliverables/patches/` and apply to copies of the tree; none was applied to this repository.

| Patch | Status | Tests |
|-------|--------|-------|
| `TLS-1.diff` | Proposed, built and tested locally on a sanitizer build | `TLS-1-regression.sh` (runnable: fails unpatched, passes patched), `TLS-1-regression.t` (designed, needs IO::Socket::SSL) |
| `CFG-1.diff` | Proposed, built and tested locally | `CFG-1-regression.t` (7/16 fail unpatched, 16/16 pass patched); `control_api.t`, `control_api_unix.t` 106/106 on patched |
| `CFG-F-1.diff` | Proposed, built and tested locally | UBSan line gone on patched |
| `HTTP-1.diff` | Proposed, built and tested locally | `HTTP-1-regression.t` (1/13 fail unpatched, 13/13 pass patched); `tunnel*.t` 34/34 on both |
| `MEM-1.diff` | Proposed, tested in standalone harness | `regress.c` 16/36 fail unpatched, 0/36 patched; fuzz 1M parses per seed |

No fix has been merged upstream. No commit was created.

## 10. Areas reviewed without identified vulnerabilities

- HTTP/1 request line, header line, complex URI normalization, chunked parsing, status line, `ngx_http_arg`/`split_args`; duplicate Content-Length, TE plus CL, obs-fold, bare CR and NUL all rejected; CONNECT branches (port mandatory, HTTP/1.1 mandatory, URI pinned).
- HTTP/2: HPACK static and dynamic tables, CONTINUATION, padding, flow control, settings and ping flood caps, DATA versus Content-Length, PRIORITY_UPDATE (RFC 9218) node lifecycle. HTTP/3 and QPACK: varint and prefix-int guards, literal length bounds, dynamic table base and index arithmetic. Huffman decoder.
- Upstream modules: proxy (status, headers, chunked and trailer parsing), proxy_v2 (diff-identical to grpc apart from strings), grpc, fastcgi, scgi, PROXY protocol v1/v2 and TLVs. Priority header parser.
- Memory safety: JSON parser, unescaper and renderer; `ngx_data`; script engine reserved-memory fix in HTTP and stream; variables; mp4 (CVE-2022-41741/41742 checks present), flv, range, slice, sub, SSI, addition, charset, gunzip, image, xslt, autoindex, DAV (URI restore fix present), userid, secure_link, sticky, GeoIP MMDB, string helpers, hash, array, buf, output chain, palloc, slab, resolver response parsing, file cache header parsing, upstream header buffers and early hints, event pipe.
- Configuration and process model: include/glob and dump handling, pid and lock files, shared-memory zone reuse rules, `load_module`, privilege drop order and capabilities, signal handler, channel SCM_RIGHTS validation, temp file and directory permissions, log file opening, alias post-rewrite fix, `internal` locations, predicate locations, `satisfy`, `disable_symlinks`, access, auth_basic, auth_request, realip and X-Forwarded-For chain, referer, secure_link constant-time compare, limit_req, limit_conn, try_files, index, static, geo, map, upstream zone, log escaping, syslog.
- TLS: shared-memory session cache (i2d length guard present), session-id context derivation (prevents cross-server resumption), ticket key rotation and sync, shutdown and kTLS EIO paths, read/write error transitions, OCSP stapling and validation, certificate object cache, defaults (TLS 1.2/1.3, no compression, no renegotiation), ssl_preread ClientHello parser, QUIC AEAD nonces, key update, tokens, packet-number decoding, OpenSSL compat layer, upstream certificate verification.
- QUIC transport: frame parsing, ACK ranges, stream limits and flow control, connection ID limits, migration and 3x amplification limit, stateless reset rate limiting, output sizing, BPF map inheritance.
- Mail: POP3/IMAP/SMTP parsers and literal handling, auth mechanisms, auth_http escaping, proxy response parsing. Stream: UDP sessions, limit_conn zone locking. Core concurrency: shmtx, rwlock, thread pool queue bound, accept mutex, timers, posted events, worker shutdown.
- Dynamic: 5368 official tests under ASan/UBSan with no sanitizer output.

## 11. Areas not reviewed and limitations

- Not read line by line: `ngx_http_uwsgi_module.c`, `ngx_http_v3_uni.c`, `ngx_http_v3_filter_module.c`, `ngx_http_v3_encode.c`, `ngx_http_v2_filter_module.c` beyond queue functions, large parts of `ngx_http_upstream.c` outside header and buffer handling (request-body sending, next-upstream, cache-send state machines), SSI block/config/if handlers, split_clients, stream realip and geo, most `ngx_http_variables.c` handlers, mail auth_http response parsing, ECH and certificate-compression paths, BoringSSL/QuicTLS API variants, the generated eBPF bytecode, win32 code, the perl module.
- Dynamic coverage gaps: no IPv6 in the container; SSL-based official tests skipped (no `IO::Socket::SSL`); no QUIC client, OCSP responder or kernel TLS exercised at runtime; no fuzzing of QUIC frame or mail command parsers; no binary-upgrade test with the control socket.
- The ASan build lacked the JSON HTTP module, so that consumer was analysed statically while the core parser was fuzzed standalone.
- Git history in the fork is shallow (50 commits), so regression analysis of older fixes relied on the code as it stands and on the in-repo changelog.
- Severity labels for design-level findings (CFG-1, HTTP-1) depend on deployment and were rated as hardening items rather than vulnerabilities, consistent with `SECURITY.md`.

## 12. Recommended next steps

1. Submit TLS-1 to the nginx security team as a hardening proposal with the patch and the shell regression; ask whether a 421 in the no-SNI case or a documentation change is preferred.
2. Land the CFG-1 documentation paragraph and audit logging; decide on loopback enforcement or an authorization mechanism before the Control API leaves experimental status.
3. Document the `tunnel_pass` security model and the allow-list pattern; consider a built-in destination allow-list directive; fix the `CONNECT host:0` status (HTTP-G-1) and set `u->schema` in the tunnel module (HTTP-G-2).
4. Apply the MEM-1 and CFG-F-1 one-liners and add the JSON skip regression cases to the project's tests.
5. Extend dynamic testing to the gaps listed in Section 11: an IPv6-capable host with `IO::Socket::SSL`, a QUIC client fuzz harness for `ngx_quic_parse_frame`, and mail command fuzzing under sanitizers.

## Appendix: deliverables layout

- `AUDIT-REPORT.md`: this report.
- `audit-deliverables/patches/`: `TLS-1.diff`, `TLS-1-regression.sh`, `TLS-1-regression.t`, `CFG-1.diff`, `CFG-F-1.diff`, `CFG-1-regression.t`, `HTTP-1.diff`, `HTTP-1-regression.t`, `MEM-1.diff`.
- `audit-deliverables/agent-reports/`: discovery reports (`REPORT-*.md`), validation reports (`VAL-*.md`), variant and remediation reports (`GH-*.md`), the finding tracker (`TRACKER.md`), and the sanitizer sweep note.

These two paths are new, untracked files added to the working directory for delivery; no tracked file was changed and nothing was committed.
