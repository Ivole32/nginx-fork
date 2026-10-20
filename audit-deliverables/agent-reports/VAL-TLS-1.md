# VAL-TLS-1 — Independent validation of TLS-1 (per-vhost client-cert policy vs. SNI-less / unmatched-SNI connections)

Validator: Agent F. Revision: b38c9d8 (1.31.8 dev), ASan+UBSan build, OpenSSL 3.0.13, loopback only (ports 18600-18605).
Artifacts: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/val-tls1/` (nginx.conf, drive.sh, results.txt, logs/error.log, certs/ copied from Agent E).

## Conclusion: **Known limitation (design behaviour), reproduced; not a memory/logic defect in the sense of a broken check — but a genuine, cheap-to-close policy gap worth a hardening recommendation.**

- Agent E's observation is **factually correct and fully reproduced** (HTTP/1.x and HTTP/2): a client that omits SNI, or sends an SNI that matches no `server_name`, is handshaken by the listen's default server; the request is then routed by `Host`/`:authority` to another vhost on the same socket, and that vhost's `ssl_verify_client`/`ssl_client_certificate` is enforced only against the *default server's* verification result.
- I classify it as (b) **documented/intended design of SNI-less vhosting** rather than (a) a code defect: nginx's model is "no (matching) SNI => the default server owns the TLS layer", the 421 guard was deliberately scoped to the SNI-present case (changelog 1.11.0: "requests to a virtual server different from one negotiated during an SSL handshake"), and the upstream test-suite explicitly codifies "absent sni => default server" (ssl_reject_handshake.t) and carries a TODO acknowledging that Host != SNI is otherwise not restricted (ssl_sni.t "sni restrictions"). Nothing in the repo documents the no-SNI + different-CA case specifically, so "documented" is only partially true; "intended" is well supported.
- It is **not a false positive**. The practical gap is narrower than TLS-1's title suggests: it requires that the default (or any SNI-unmatched fallback) server on the same socket itself *requests and accepts* client certificates from a trust anchor the attacker can satisfy (S4 shows that a default server with no `ssl_verify_client` fully protects the sibling vhost, because no CertificateRequest is ever sent and `SSL_get_peer_certificate()` is NULL).

---

## Q1 — Code trace: which SSL_CTX governs, and which `sscf->verify`/CA is consulted

All line numbers from `/home/user/nginx-fork/src/http/ngx_http_request.c` at b38c9d8 (verified by reading).

1. **Connection setup** — `ngx_http_init_connection()` line 309: `hc->conf_ctx = hc->addr_conf->default_server->ctx;` The connection starts bound to the listen's default server.
2. **Handshake creation** — `ngx_http_ssl_handshake()` lines 778-781: `sscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_ssl_module); ... ngx_ssl_create_connection(&sscf->ssl, c, NGX_SSL_BUFFER)`. The SSL object is created from the **default server's `SSL_CTX`**, which already carries that server's `SSL_CTX_set_verify(SSL_VERIFY_PEER,...)` and `SSL_CTX_set_client_CA_list()` (set in `ngx_ssl_client_certificate()`, `src/event/ngx_event_openssl.c:944-1061`, called from `ngx_http_ssl_merge_srv_conf()` at `src/http/modules/ngx_http_ssl_module.c:849-863` only when `conf->verify` is set).
3. **SNI callback** — `ngx_http_ssl_servername()` lines 886-1030:
   - no SNI: `SSL_get_servername()==NULL` -> `goto done` (line 922-928). `hc->ssl_servername` stays **NULL**, `hc->conf_ctx` stays the default server, SSL_CTX unchanged.
   - unmatched SNI: `ngx_http_find_virtual_server(...)` returns `NGX_DECLINED` -> `goto done` (line 954-962). Same result: `hc->ssl_servername` **NULL**, default SSL_CTX.
   - matched SNI: `hc->ssl_servername` set (965-970), `hc->conf_ctx = cscf->ctx` (972), `SSL_set_SSL_CTX()` + `SSL_set_verify()`/`SSL_set_verify_depth()` copied from the matched server's ctx (983-995).
   - `done:` only applies `ssl_reject_handshake` of whatever `hc->conf_ctx` now is (1020-1029).
   So for both the no-SNI and the unmatched-SNI cases the **default server's verify mode and CA list drive the CertificateRequest and the chain verification**.
4. **Request routing** — `ngx_http_set_virtual_server()` lines 2475-2555. Both the "Host equals negotiated SNI -> short-circuit" block (2490-2504) and the "Host differs from negotiated name and target has verify -> 421" block (2521-2538) are inside `if (hc->ssl_servername)`. With `hc->ssl_servername == NULL`, control goes straight to `ngx_http_find_virtual_server()` (2508-2510) and then to `r->srv_conf = cscf->ctx->srv_conf` (2548). The request is re-homed to the Host-selected server with **no comparison against the negotiated TLS server**.
5. **Verification re-check** — `ngx_http_process_request()` lines 2147-2192: `sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module)` is the **Host-selected** server's config, but `SSL_get_verify_result()` (2150) and `SSL_get_peer_certificate()` (2168) read the result of the handshake that was performed under the **default server's** CA list. The target's `ssl_client_certificate` is never consulted post-handshake; only its `verify` level (on/optional/optional_no_ca) is applied to the foreign verification result.

Note that `hc->conf_ctx` does faithfully record the negotiated server; the guard keys off `hc->ssl_servername` (presence of a matched SNI) rather than off "routed server != negotiated server". That is the exact root cause of the gap Agent E describes, and it also means a minimal hardening fix exists (see Mitigations).

## Q2 — Independent reproduction (ASan build, my own config)

Config: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/val-tls1/nginx.conf` (5 scenarios), driver `drive.sh`, full transcript `results.txt`. Certs: caA/caB self-signed, clientA signed by caA, clientB by caB (verified with `openssl verify`). All requests: `printf 'GET / HTTP/1.0\r\nHost: <host>\r\n\r\n' | openssl s_client -connect 127.0.0.1:<port> -quiet [-noservername | -servername X] [-cert ... -key ...]`. ASan/LSan reported nothing (0 "AddressSanitizer" lines).

**S1 (18600) = Agent E's scenario: A default_server, `ssl_verify_client optional` + caA; B `ssl_verify_client on` + caB; `http2 on`.**

| # | SNI | client cert | Host | Result |
|---|-----|-------------|------|--------|
| S1-1 | none | clientA (caA) | b.example | **200** `server=B(PROTECTED) verify=SUCCESS dn=CN=clientA sni=` — bypass reproduced |
| S1-2 | none | clientA | a.example | 200 server=A (control) |
| S1-3 | none | none | b.example | 400 ("client sent no required SSL certificate") |
| S1-4 | none | clientB (caB) | b.example | **400** "verify error: (21:unable to verify the first certificate)" — the *legitimate* B client is rejected because A's CA list was used |
| S1-5 | a.example | clientA | b.example | 421 Misdirected Request ("server name different from the one that was negotiated") |
| S1-6 | b.example | clientA | b.example | 400 verify error 21 (B's CA correctly applied) |
| S1-7 | b.example | clientB | b.example | 200 server=B verify=SUCCESS dn=CN=clientB (legit) |
| S1-8 | c.example (unknown) | clientA | b.example | **200** `server=B(PROTECTED) verify=SUCCESS dn=CN=clientA sni=c.example` — bypass via unmatched SNI reproduced |

HTTP/2 (curl 8.5.0/nghttp2, IP-literal => curl sends no SNI; `--noproxy '*'` needed for hostname URLs in this sandbox):
- H2-1 `curl -sk --http2 --cert clientA.crt --key clientA.key -H 'Host: b.example' https://127.0.0.1:18600/` -> **200** `proto=HTTP/2.0 server=B(PROTECTED) verify=SUCCESS dn=CN=clientA sni=`.
- H2-2 `curl -sk --noproxy '*' --http2 --resolve a.example:18600:127.0.0.1 --cert clientA ... -H 'Host: b.example' https://a.example:18600/` (SNI=a, :authority=b, i.e. the coalescing case) -> **421**.
- H2-3 no cert, no SNI, Host b.example -> 400.
- H2-4 SNI=c.example (unknown), clientA, :authority=b.example -> **200** server=B(PROTECTED).

Error log confirmed the routed server for each case (`server: b.example` on the 400s, `server: a.example` on the 421).

## Q3 — Documentation and test-suite evidence

- The repo does **not** vendor the module reference (`docs/xml/en` is absent; only `docs/xml/nginx/changes.xml`, xslt, dtd, html). So `ssl_verify_client`/`ssl_reject_handshake` prose could not be checked in-repo.
- `docs/xml/nginx/changes.xml` line 8136 (ver 1.11.0, 2016-05-24): "the "421 Misdirected Request" response now used when rejecting requests to a virtual server different from one negotiated during an SSL handshake; this improves interoperability with some HTTP/2 clients when using client certificates." The wording and the h2 motivation show the guard targets the *SNI-negotiated-then-different-Host* case (HTTP/2 coalescing). Related entries: 1.1.2 (line 14965) "ssl_verify_client ... might work incorrectly if SNI was used"; 1.27.4 (line 1933) CVE-2025-23419 "insufficient check in virtual servers handling with TLSv1.3 SNI allowed to reuse SSL sessions in a different virtual server, to bypass client SSL certificates verification" — upstream has treated *session-reuse* cross-vhost verification bypass as a security bug, but that fix (`sni_accepted`/session-id-context) addresses resumption, not the no-SNI fresh-handshake path. 1.29.2 (line 1603) is a follow-up to that fix. Git history is unavailable locally (shallow clone, 50 commits, all lines blame to the grafted root df5269c), so I could not trace the original author's intent beyond the changelog.
- nginx-tests `ssl_verify_client.t`: every `get()` passes `SSL_hostname => $sni` — **no test sends no-SNI with a mismatched Host**. Its only 421 case (line 180) is SNI=optional, Host=localhost. `h2_ssl_verify_client.t` line 97 likewise tests SNI=localhost / :authority=example.com -> 421. So the no-SNI case is neither tested as a bypass nor as "must be rejected".
- `ssl_sni.t` lines 106-115: tests expecting 400 for "host exists, sni exists, and host is not equal sni" and "host not found, sni exists" are wrapped in `TODO: 'sni restrictions'` — upstream explicitly acknowledges that nginx does not, in general, restrict Host != SNI; the "host exists, sni not found" case is asserted to succeed (line 102-103) with the request routed by Host. This is the upstream-blessed semantic that TLS-1 builds on.
- `ssl_reject_handshake.t` lines 106 and 112: "absent sni rejected" / "absent sni accepted" — the suite explicitly tests that a **missing SNI is handled by the default server's policy**. This is the strongest in-tree evidence that "no SNI => default server governs the TLS layer" is intentional, and that `ssl_reject_handshake` on the default server is the designed way to close that door.

## Q4 — Variants and mitigations (all tested)

- **Both servers `on`, different CAs (S2, 18601)**: same confusion. S2-1 noSNI+clientA+Host b -> **200 server=B verify=SUCCESS dn=CN=clientA**; S2-3 unknown SNI -> 200; S2-2 noSNI+clientB -> 400 (legit B client rejected under A's CA). The verify *level* is irrelevant; what matters is that the default server's CA list differs from (and is satisfiable independently of) the target's.
- **`ssl_reject_handshake on` on the default server (S3, 18602)**: fully mitigates. S3-1 (noSNI) and S3-2 (unknown SNI) fail at the TLS layer with alert 112 "unrecognized name" ("handshake rejected while SSL handshaking" in error.log); S3-3 legit -> 200; S3-4 wrong CA with correct SNI -> 400. No HTTP request ever reaches B without B's own SSL_CTX.
- **Default server without `ssl_verify_client` (S4, 18603)**: also fully mitigates. No CertificateRequest is sent, so S4-1/S4-2/S4-3 all -> 400 "client sent no required SSL certificate" (log *63-*65). Hence the attack precondition is specifically "the default/fallback server requests client certs under a CA the attacker can satisfy", not merely "two vhosts share a socket".
- **Separate listen (S5, 18604/18605)**: fully mitigates. On B's own socket the default server *is* B, so noSNI+clientA -> 400 (verify error under caB), noSNI+clientB -> 200. (S5-3: Host b.example on A's socket is served by A — expected, since B is not on that socket.)
- Also observed: the semantics cut both ways — in S1-4/S2-2 a legitimate caB client that omits SNI is rejected. So an operator who mixes CAs on one socket already has a functional reason to notice this behaviour.

## Q5 — HTTP/2 and HTTP/3

- HTTP/2: `ngx_http_v2_parse_authority()` (`src/http/v2/ngx_http_v2.c:3573-3612`) runs `ngx_http_validate_host()` then `ngx_http_set_virtual_server(r, value)` — the same function and the same `hc->ssl_servername` gate. `:authority`/`Host` mismatch is rejected (lines 4028-4040). Connection coalescing (browser reuses an SNI=a connection for b) hits the SNI-present branch and gets 421 (H2-2), which is exactly what the 1.11.0 change was for. The no-SNI/unmatched-SNI gap is identical to HTTP/1.x (H2-1, H2-4) — HTTP/2 neither widens nor narrows it.
- HTTP/3: `ngx_http_v3_init()` (`src/http/v3/ngx_http_v3_request.c:60-95`) copies `ssl_servername`, `ssl_servername_regex` and `conf_ctx` from the QUIC parent connection (`phc`) to each stream's `hc`; `:authority` is routed through the same `ngx_http_set_virtual_server()` (line 987). So the logic is the same as for h1/h2. Not executed (curl here has no HTTP/3); in practice QUIC clients always send SNI, so only the *unmatched-SNI* variant is realistic there.
- UBSan noise seen during h2 runs ("store to misaligned address" at ngx_http_v2.c:2837 etc.) comes from the intentional `NGX_HAVE_NONALIGNED` fast paths (`src/http/v2/ngx_http_v2.h:336,360`); unrelated to TLS-1, not a finding.

## Existing mitigations (any one suffices)
1. `ssl_reject_handshake on;` in the listen's default server (available since 1.19.4, tested above) — rejects no-SNI and unknown-SNI handshakes outright.
2. Do not configure `ssl_verify_client` on the default server of a socket that hosts a differently-trusted protected vhost (S4).
3. Give the client-cert-protected vhost its own listen address/port (S5).
4. Use the same `ssl_client_certificate` on all servers of a socket and differentiate by `$ssl_client_s_dn`/`$ssl_client_verify` in the app or with `if` — then there is no CA confusion to exploit.
5. Code-level hardening (suggestion, not upstream code): in `ngx_http_set_virtual_server()` key the mismatch check on `cscf->ctx != hc->conf_ctx` (routed server differs from the server whose SSL_CTX performed the handshake) instead of on `hc->ssl_servername != NULL`, with the existing `sscf->verify` condition. This would make S1-1/S1-8/S2-1/S2-3/H2-1/H2-4 return 421 while leaving plain (non-verifying) vhosting untouched.

## Severity (realistic)
- Impact when the precondition holds: full bypass of the protected vhost's client-certificate authentication by anyone holding a certificate accepted by the default/fallback server (a lower-privilege credential), from the network, no user interaction. C and I of that vhost's resources; no availability impact; no memory-safety aspect.
- Precondition: shared listener; protected vhost is not the default; the default server itself requests client certs under a different trust anchor that the attacker legitimately satisfies; no `ssl_reject_handshake`. This is a specific, somewhat unusual deployment (mixed-CA mTLS on one socket), and nginx's model already sends a signal to such operators (legit clients without SNI break). 
- I would rate it **Medium** as a hardening item / design limitation, not a vulnerability requiring an advisory in its own right, because the behaviour is the upstream-tested "default server governs" semantic and documented mitigations exist. If treated as a vulnerability: CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N (AT:P for the specific config; PR:L because a valid cert from the default server's CA is required; VC/VI set to H on the assumption that the protected vhost's data is sensitive — lower if not). I do not assign a numeric score.

## Remaining uncertainty
- I could not confirm offline whether upstream has a public ticket classifying the no-SNI case as won't-fix; the in-tree evidence (ssl_reject_handshake.t "absent sni", ssl_sni.t TODO, the 1.11.0 changelog) supports "intended", but the module documentation itself was not available in this repo.
- Git history is shallow, so the original rationale for gating on `hc->ssl_servername` rather than on the negotiated server is inferred from the changelog, not from commit messages.
- HTTP/3 path read but not executed.
- Did not test TLS 1.2 vs 1.3 separately (OpenSSL 3.0.13 defaulted to TLS 1.3); the gate is independent of protocol version in the code, so I expect no difference.
