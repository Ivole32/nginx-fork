# VAL-HTTP-1 — Independent Validation of HTTP-1 and HTTP-2 (Agent F)

Scope: validate/disprove Agent B findings HTTP-1 (`tunnel_pass` default target is client-controlled → open CONNECT forward proxy / SSRF) and HTTP-2 (`allow_connect` is server-wide → CONNECT reaches non-tunnel handlers).

Target: `/home/user/nginx-fork` @ b38c9d8 (nginx/1.31.8 dev). Dynamic tests run against the ASan+UBSan build at `.../scratchpad/build-asan/nginx` (confirmed: `nginx -V` shows `--with-debug ... -fsanitize=address,undefined`, and `ngx_http_tunnel_module` is compiled in — it is a default module). All tests on loopback ports 18800–18899. No repo files modified; all artifacts under `.../scratchpad/audit/val-http1/`.

---

## Claim HTTP-1 — Conclusion: CONFIRMED BEHAVIOR, but it is a DESIGN DECISION (intended forward-proxy feature), not a defect. Reclassify as "insecure-once-enabled default / docs+hardening gap." Severity Low–Medium; Confidence High on behavior.

### Code evidence (verified by reading)
- `src/http/modules/ngx_http_tunnel_module.c:469-471`: zero-argument form defaults the target to `$host:$request_port`:
  ```c
  if (cf->args->nelts == 1) {
      ngx_str_set(&url, "$host:$request_port");
  } else {
      url = value[1];
  }
  ```
- `ngx_http_tunnel_eval()` :463-485 runs that script per request and `ngx_parse_url()` with `url.no_resolve = 1`, taking host/port straight from the request. The destination derives from `$host`/`$request_port`, i.e. the CONNECT authority.
- Request-line authority → `r->headers_in.server`, `r->port` at `src/http/ngx_http_request.c:1183-1203` (via `ngx_http_validate_host`). Those feed `$host`/`$request_port`.
- After `ngx_http_tunnel_process_header()` (`ngx_http_tunnel_module.c:287-305`) sets `u->upgrade = 1`, nginx becomes a bidirectional byte pipe (`ngx_http_upstream_upgrade`). Confirmed `u->upgrade = 1` is set ONLY in the tunnel module (:303) and in the proxy module's 101-Switching-Protocols path (`ngx_http_proxy_module.c:2038-2044`).
- There is NO destination allow-list, port allow-list, or private-range default-deny anywhere in the module. Access control is left to generic directives (`allow`/`deny`, `auth_basic`).

### Intent / documentation findings
- `docs/` contains **no** reference documentation for the tunnel module (`find docs -iname '*tunnel*'` → nothing; `grep -rn tunnel_pass docs/` → nothing). The only in-repo mentions are in `docs/xml/nginx/changes.xml`: a feature entry for `tunnel_socket_sndbuf`/`tunnel_socket_rcvbuf` (:585-593) and a generic "Bugfixes and improvements in the ngx_http_tunnel_module" (:691-694). No statement that access control is mandatory.
- Official test suite shows the **intended deployment** and that the client-controlled, loopback-reaching behavior is deliberate:
  - `nginx-tests/tunnel.t` configures the **zero-arg** form (`location / { ... tunnel_pass; }`), `tunnel_pass tunnel_upstream;`, and `tunnel_pass $host:$request_port;`. It asserts `CONNECT 127.0.0.1:$p` → `SEE-THIS` (i.e. forwarding to **loopback** is an expected, passing test), plus `CONNECT example.net:$p` via resolver → `SEE-THIS`. So forwarding to a client-chosen host/port, including 127.0.0.1, is tested behavior.
  - `nginx-tests/tunnel_auth_basic.t` is titled "http tunnel module with auth_basic", realm `"closed proxy"`, uses the zero-arg `tunnel_pass;`, and asserts `407` without credentials and success with them. This is the documented way to secure the proxy.
- Net: the module is an **intentional CONNECT forward-proxy feature**. The open-proxy property is inherent to that feature and the project's own tests demonstrate access control (`auth_basic`, and by extension `allow`/`deny`) as the operator's responsibility. This is not a code defect; it is an insecure-by-default-once-enabled design that merits a documentation/hardening note.

### Reproduction (ASan build, loopback)
Config (`.../val-http1/conf/nginx.conf`): `server{listen 127.0.0.1:18800; location / { tunnel_pass; }}` plus variants (18801 fixed target `tunnel_pass 127.0.0.1:18850`, 18802 `deny all`, 18803 `auth_basic`). "Internal" service = python TCP listener on 127.0.0.1:18850 that logs bytes and echoes a banner.

- **A — open proxy (18800), zero-arg:** client sends `CONNECT 127.0.0.1:18850 HTTP/1.1` + Host, then raw bytes.
  - Proxy response: `HTTP/1.1 200 OK ... Connection: close`.
  - Client bytes `PING-FROM-CLIENT-THROUGH-TUNNEL` arrived at the internal service (its log: `received 31 bytes: b'PING-FROM-CLIENT-THROUGH-TUNNEL'`), and the service banner came back to the client. **Full bidirectional tunnel to a client-chosen loopback target — confirmed.**
- **B — explicit fixed target (18801):** client sends `CONNECT 127.0.0.1:19999` (bogus), bytes still reached the configured `127.0.0.1:18850`. Confirms that with a non-variable `tunnel_pass <target>`, `tunnel_lengths == NULL`, `ngx_http_tunnel_eval` is skipped, and the client authority is **ignored** — fixed-target configs are safe.
- **C — `deny all` (18802):** `HTTP/1.1 403 Forbidden`; error log `access forbidden by rule`. Access control applies to CONNECT.
- **D — `auth_basic`, no creds (18803):** `HTTP/1.1 407 Proxy Authentication Required` + `Proxy-Authenticate: Basic realm="closed proxy"`. nginx uses the proxy-auth variant for CONNECT (`ngx_http_core_module.c:2069` reads `Proxy-Authorization` via `ngx_http_proxy_auth`).
- **E — `auth_basic`, valid creds:** `HTTP/1.1 200 OK`, bytes reached the target. Confirms the "closed proxy" deployment works.

No ASan/UBSan errors in any run (`grep -iE 'sanitizer|runtime error|SUMMARY|heap-|SEGV'` over nginx stdout + error.log → none).

### Severity calibration vs other servers (from knowledge)
- **Apache `mod_proxy_connect`**: CONNECT requires `ProxyRequests On` + `AllowCONNECT`, which **defaults to ports 443 and 563 only**; reaching arbitrary ports needs explicit widening, and `<Proxy>` access control is expected.
- **Squid**: forward proxy by design, but ships `http_access deny all` posture plus `Safe_ports`/`SSL_ports` ACLs that restrict CONNECT to 443 by default; an open relay requires the admin to loosen ACLs.
- **Envoy**: CONNECT is explicit per-route opt-in (`connect_config`/upgrade), normally paired with RBAC; no implicit open proxy.
- **nginx tunnel module**: fully opt-in (must add `tunnel_pass` — good), but once the zero-arg form is used there is **no port allow-list and no default destination deny** — more permissive than Apache/Squid defaults, which both restrict CONNECT to 443/563-class ports out of the box. This is the real gap: nginx lacks a `Safe_ports`/`AllowCONNECT`-style built-in restriction, so a copy-paste of the zero-arg form yields a wide-open relay (loopback, 169.254.169.254, RFC1918, any port).

### Realistic impact
C/I via SSRF/open-relay **iff** an operator deploys the variable/zero-arg `tunnel_pass` on a reachable listener **without** `allow`/`deny`/`auth_basic`. This is plausible (the zero-arg form is the simplest and appears in tests), but it is an operator action, not a flaw triggerable against a default or fixed-target config. Fixed-target `tunnel_pass host:port` is not exploitable (variant B).

### Mitigations
- Operator: use `auth_basic` and/or `allow/deny`, or a fixed/validated target, or restrict the port via a variable map. All verified to work (variants B–E).
- Upstream hardening suggestions (optional): document the security requirement in the module docs; consider an opt-in destination/port allow-list (a `Safe_ports` analogue) or a default deny of loopback/link-local/private ranges for the variable form.

### Remaining uncertainty
- With `resolver` set + zero-arg form, a client hostname containing sub-delims/`%`/`'` (now accepted by `ngx_http_validate_host`) reaches `ngx_resolver`. Agent B judged this bounded by the 255/63 length limits; I did not independently re-audit the resolver name encoder. Flag for whoever owns the resolver area.

---

## Claim HTTP-2 — Conclusion: MECHANISM CONFIRMED, but security consequence REJECTED (no SSRF, no smuggling). It is a configuration oddity / robustness issue only. Severity Low (informational); Confidence High.

### Code evidence
- `ngx_http_tunnel_module.c:465`: `cscf->allow_connect = 1;` on `cscf = ngx_http_conf_get_module_srv_conf(...)` — **server-wide**, set when `tunnel_pass` appears in ANY location of the server (also on the `limit_except`/noname merge path, :432-436).
- `ngx_http_request.c:2098-2104`: the CONNECT gate checks only `cscf->allow_connect` (server conf via `ngx_http_get_module_srv_conf`) and HTTP/1.1 — not which location/handler.
- `ngx_http_parse.c:737-740`: a CONNECT request's URI is pinned to `"/"`:
  ```c
  if (r->method == NGX_HTTP_CONNECT) {
      r->uri_start = p;      /* the '/' in "HTTP/1.1" */
      r->uri_end = p + 1;
  }
  ```
  Consequence I verified: because the URI is always `"/"`, a CONNECT can only ever match the location that serves `"/"`. A `location = /t { tunnel_pass; }` is therefore **unreachable by CONNECT** — the method routes to whatever handles `"/"` (here `location / { proxy_pass ... }`).

### Reproduction
Config: `server{listen 127.0.0.1:18810; location / { proxy_pass http://127.0.0.1:18851; } location = /t { tunnel_pass; }}`. Backend on 18851 logs the request line and replies `HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n`, then tries to read more.

Client sends `CONNECT 127.0.0.1:18851 HTTP/1.1` + Host, then raw bytes `RAW-BYTES-AFTER-CONNECT`.
- Backend received verbatim: `b'CONNECT / HTTP/1.1\r\nHost: 127.0.0.1:18851\r\n\r\n'` — method `CONNECT` copied, URI `/`. Confirms CONNECT reached the **proxy** handler.
- Client got: `HTTP/1.1 200 OK ... Content-Length: 0 ... Connection: close`.
- **Backend post-200 recv: 0 bytes. Client bytes-back after payload: empty.** The client's raw bytes reached **neither** the backend nor came back. No byte pipe exists.

### Why there is no security consequence (verified)
- The proxy handler sets `u->upgrade = 1` **only** on a `101 Switching Protocols` response *and* a client `Upgrade` header (`ngx_http_proxy_module.c:2038-2044`). A plain CONNECT (no `Upgrade`) with a 2xx does not upgrade, so nginx stays in normal proxy mode, relays the backend's framed response, and closes (`Connection: close`). There is no raw client→backend channel.
- Even the forced-upgrade variant (client sends `CONNECT` + `Upgrade:` and the backend answers `101`) would tunnel only to the **statically configured** `proxy_pass` upstream — never a client-chosen host. So it grants no reach the client didn't already have via a normal WebSocket request. **Not SSRF.**
- No request smuggling: the CONNECT has no body (rejected at `ngx_http_request.c:2105-2110`), pipelined bytes after it were dropped (connection is `close`, not keepalive), and nginx's own framing governs the response.
- Net effect: a client receives a `200` that *looks* like an established tunnel but isn't, and a backend sees an odd `CONNECT /` line (most real backends 400/405 it). Pure confusion/robustness, requiring the operator to mix `tunnel_pass` and a non-tunnel handler in one server.

No ASan/UBSan errors.

### Mitigation
Don't mix `tunnel_pass` with other handlers in the same `server`; put CONNECT proxies in a dedicated `server{}`. Optional upstream hardening: gate CONNECT on the matched location's handler actually being the tunnel handler (so a stray `tunnel_pass` elsewhere doesn't expose other handlers to CONNECT), and/or warn when `tunnel_pass` sits in a non-`/` location where CONNECT can never reach it.

---

## New candidates (none rise to a vulnerability)

### HTTP-F-1 (Low / informational) — `tunnel_pass` in a location that cannot serve `"/"` is silently dead for CONNECT
Because `ngx_http_parse.c:737-740` pins the CONNECT URI to `"/"`, a `tunnel_pass` placed in any location that does not match `"/"` (e.g. `location = /connect`, `location /proxy/`) can never handle a CONNECT; the method routes to the `"/"` handler instead. This is a configuration footgun (the intended tunnel never runs, and if a non-tunnel handler owns `"/"`, that is the HTTP-2 oddity). Suggest a config-time warning. Not independently security-relevant beyond HTTP-2.

### HTTP-F-2 (Low / hardening) — no built-in CONNECT port/destination restriction (Safe_ports analogue)
Unlike Apache's `AllowCONNECT` (default 443/563) and Squid's `Safe_ports`, the tunnel module imposes no port or destination restriction for the variable/zero-arg form; any port 1–65535 and any routable host (loopback/link-local/RFC1918) is reachable once enabled without `allow`/`deny`/`auth_basic`. This is the concrete, defensible hardening ask behind HTTP-1. Confirmed by code (no such check exists) and by variant A (reached 127.0.0.1:18850).

---

## Summary table

| Claim | Behavior real? | Security defect? | Classification | Severity | Confidence |
|------|----------------|------------------|----------------|----------|------------|
| HTTP-1 | Yes (repro A) | No (intended forward proxy; access control works, repro C/D/E) | Design decision needing docs + optional hardening | Low–Medium | High (behavior), High (design-intent, from tests) |
| HTTP-2 | Mechanism yes (repro: `CONNECT /` to backend) | No SSRF, no smuggling (no byte pipe without 101+Upgrade; even then only to static upstream) | Config oddity / robustness | Low (informational) | High |

## Artifacts
- Config: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/val-http1/conf/nginx.conf`
- Scripts: `.../val-http1/scripts/{internal_target.py,backend_logger.py,connect_client.py}`
- Logs/output: `.../val-http1/out/` and `.../val-http1/logs/error.log`
