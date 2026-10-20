# GH-HTTP-1 — Variant analysis (Agent G) and remediation / regression testing (Agent H) for HTTP-1, HTTP-2, HTTP-F-1

Repository: /home/user/nginx-fork @ b38c9d8 (1.31.8 dev). Nothing in the repository was modified.
All work is under `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-http1/` (copy of the tree in `src-http1/`, built with the ASan/UBSan configure options from `configure.log`, `--builddir`/`--prefix` inside that directory). Binaries: `nginx-orig` (unpatched copy, built from the same tree before patching) and `nginx-patched`. All dynamic tests on loopback ports 19200-19299 (plus the official tests' own 8xxx allocations).

Parent context: HTTP-1 (validated: design decision, hardening + docs), HTTP-2 (rejected as a security issue, mechanism confirmed), HTTP-F-1 (config footgun). Nothing here changes those classifications; the goal was (1) look for the same pattern elsewhere, (2) harden what is cheap and correct, (3) prove it with tests.

---

## Part 1 — Variant analysis: "a client-supplied value is the default network destination"

Verdict legend: **Defect-same-root-cause** / **Consistent-by-design** / **Not applicable**. "Verified" = read the code at the cited lines and, where marked, exercised it against `nginx-orig`.

### 1.1 Other `*_pass` directives with variables

| Item | Evidence | Verdict |
|---|---|---|
| `proxy_pass` with variables | `ngx_http_proxy_eval()` src/http/modules/ngx_http_proxy_module.c:981-1050 runs the compiled script, `url.no_resolve = 1` (:1032), then the same `u->resolved` fill as the tunnel module. Variables only appear if the operator writes them; the static form (`plcf->url = *url`, :4493, reached only when `ngx_http_script_variables_count()` is 0) ignores the client entirely. | **Consistent-by-design** (operator opt-in; identical mechanism, no default). |
| `fastcgi_pass` / `uwsgi_pass` / `scgi_pass` / `grpc_pass` with variables | `ngx_http_fastcgi_eval` :785 (`no_resolve` :799), `ngx_http_uwsgi_eval` :773 (:823), `ngx_http_scgi_eval` :583 (:597), `ngx_http_grpc_eval` :637 (:688). Same shape as 1.1; no directive defaults to a request variable. | **Consistent-by-design** |
| Does any **documented default** use `$host`? | The in-tree docs are only `docs/xml/nginx/changes.xml` and `docs/xml/change_log_conf.xml` (verified with `ls docs/xml docs/xml/*`); `grep -rn 'proxy_pass \$\|\$http_host\|fastcgi_pass \$\|grpc_pass \$\|uwsgi_pass \$\|scgi_pass \$' docs` → nothing. The **only** directive in the tree whose *default* argument is request-controlled is `tunnel_pass` (`ngx_str_set(&url, "$host:$request_port")`, src/http/modules/ngx_http_tunnel_module.c:469-471). | **Defect-same-root-cause is unique to tunnel_pass** (this is exactly HTTP-1). |
| `stream` `proxy_pass` with variables | `ngx_stream_proxy_eval()` src/stream/ngx_stream_proxy_module.c:651-696: `ngx_stream_complex_value()` → `ngx_parse_url()` with `no_resolve = 1` → `u->resolved`. Opt-in; stream has no `$host`, the usual idiom is `$ssl_preread_server_name`, which is client-controlled in the same way as `$host` but only when the operator writes it. | **Consistent-by-design** |

### 1.2 Mail `auth_http`: the auth server returns the destination

`ngx_mail_auth_http_process_headers()` src/mail/ngx_mail_auth_http_module.c:755-813 requires `Auth-Server` and `Auth-Port`, parses the address with `ngx_parse_addr()` (:782, numeric address only, no DNS) and checks `1 <= port <= 65535` (:803). The auth server is a configured, operator-controlled endpoint; the client never supplies the destination (it supplies the login, which the auth server maps). Loopback/RFC1918 targets are the normal case (the backend IMAP/POP/SMTP is internal). Verdict: **Consistent-by-design / Not applicable** (trusted peer by definition; sane port and address validation present).

### 1.3 `ngx_http_upstream.c` resolver use with a hostname variable

src/http/ngx_http_upstream.c:742-835: if the evaluated target is not an IP literal, `u->resolved->sockaddr` is NULL and nginx goes to `ngx_resolve_start(clcf->resolver, ...)` (:806); with no `resolver` the request fails 502 "no resolver defined to resolve %V" (:813-819, **verified dynamically**: `CONNECT LOCALHOST.:19201` → 502, error log `no resolver defined to resolve localhost`). With a `resolver`, whatever the DNS answers (including 127.0.0.1 — exactly what the official `tunnel.t` DNS stub does for `example.net`) becomes the peer. There is no post-resolution address filter anywhere in the upstream machinery (no hook between `ngx_http_upstream_resolve_handler` and `ngx_http_upstream_connect`). Verdict: **Consistent-by-design** for proxy_pass-with-variables (opt-in); for tunnel_pass it is part of HTTP-1. Consequence for hardening: **a `$host` deny-list is not a safe control; only a host allow-list (operator-chosen names) plus a port allow-list is** (see Part 2.3).

### 1.4 `$host` vs `$http_host`

`$host` (src/http/ngx_http_variables.c:1233-1254) is `r->headers_in.server`, which only ever comes from `ngx_http_validate_host()` (src/http/ngx_http_request.c:2277-2471): lower-cased (:2318-2320, :2461), port stripped (:2332-2334), one trailing dot stripped (:2447-2449), empty host rejected (:2451-2453), charset limited to alnum, `-`, `.`, `_`, `~`, sub-delims, `%` and bracketed IPv6 literals. `$http_host` is the raw header (case and port preserved). Any allow-list must be written against `$host`; this is what the reference config does. Verdict: **Consistent-by-design**; note for docs only.

### 1.5 `proxy_redirect` / `Location` rewriting

`proxy_redirect default` is synthesised from `conf->url` (src/http/modules/ngx_http_proxy_module.c:4019-4054), which is only set for a **static** `proxy_pass` (:4493). With a variable `proxy_pass`, `plcf->url.data == NULL` and `proxy_redirect default` is a config error (:4553-4560). The rewrite therefore never derives from `$host`. Verdict: **Not applicable**.

### 1.6 Tunnel-module specifics (all **verified dynamically** against `nginx-orig` with `server { listen 127.0.0.1:19200; location / { tunnel_pass; } }`, backend on 127.0.0.1:19201; raw output in `gh-http1/probe/`)

| Question | Code | Observed | Verdict |
|---|---|---|---|
| Does `ngx_http_tunnel_eval` validate the port range / reject an empty host? | It relies on `ngx_parse_url()`: `ngx_parse_inet_url()` src/core/ngx_inet.c:856-861 rejects ports outside 1..65535, :950-953 rejects an empty host. Upstream of that, `ngx_http_validate_host()` already rejects ports > 65535 (:2432-2434) and an empty host (:2451), and the request-line parser requires a colon and a digit for CONNECT (src/http/ngx_http_parse.c:398-400, :475-477, :488-495). | `example.net:65536`, `:19201`, `:` → 400 (official `tunnel.t` cases, pass). **`CONNECT 127.0.0.1:0` → 500** with error log `invalid port in upstream "127.0.0.1:"`: port 0 passes `validate_host` (it only caps at 65535), `$request_port` renders empty for `r->port == 0` (ngx_http_variables.c:1571), so the target becomes `127.0.0.1:` and `ngx_parse_inet_url` fails. Leading zeros (`:00019201`) are accepted and work. | Robustness nit only → **HTTP-G-1** below. |
| `Host:` differing from the CONNECT authority — which wins? | Authority is processed first (ngx_http_request.c:1178-1203) and sets `r->headers_in.server`/`r->port`; `ngx_http_process_host()` returns early when `server.len` is already set (:1903-1905) after validating the header (:1889, 400 if invalid). A `Host` header is still mandatory for HTTP/1.1 (:2035-2040). | `CONNECT 127.0.0.1:19201` + `Host: evil.example:1` → 200, bytes reached 127.0.0.1:19201. `CONNECT 127.0.0.1:19201` + `Host: [::1]:19202` → same. No `Host` → 400. | **Consistent-by-design** (authority always wins; `Host` cannot redirect the tunnel). |
| Can the authority carry userinfo or odd forms that bypass a naive `$host` check? | Request-line `sw_host` admits only alnum, `.`, `-` (ngx_http_parse.c:376-385); `@`, `%`, `/`, `?`, `#` and a scheme are rejected for CONNECT (:398-400, :413-423, :488-495). Bracketed IPv6 literals are accepted (:427-466) and `$host` then equals `"[::1]"` etc. Dotted-decimal shortcuts are **not** parsed as IPs by `ngx_inet_addr()` and go to DNS. | `user@127.0.0.1:19201` → 400; `127.0.0.1%2e:19201` → 400; `unix:/tmp/x` → 400; `[::1']:19202` → 500 (`invalid IPv6 address in upstream`); `[::1]:19202` and `[::ffff:127.0.0.1]:19201` → nginx **attempted** the connect (`socket() failed (97: Address family not supported)` — this container has no IPv6; on a dual-stack host `[::ffff:127.0.0.1]` reaches IPv4 loopback); `2130706433`, `0x7f.1`, `127.1` → sent to the resolver (502 here, no resolver). `LOCALHOST.` → `localhost`. | **Consistent-by-design**, but it proves a `$host` *deny-list* (`if ($host = 127.0.0.1)`) is bypassable via `[::1]`, `[::ffff:127.0.0.1]`, `localhost`, DNS names → the hardening must be an allow-list. |
| Is `$request_port` ever 0/empty? | `ngx_http_variable_request_port()` ngx_http_variables.c:1554-1576 emits "" when `r->port == 0`; for CONNECT that only happens with an explicit `:0` (port is mandatory). For non-CONNECT requests it is empty whenever `Host` has no port — irrelevant to the tunnel (handler rejects non-CONNECT with 405, tunnel module :188-190). | `CONNECT 127.0.0.1:0` → 500 (see above). | **HTTP-G-1** (nit). |
| Names with `%` / `'` / sub-delims reaching `ngx_resolver_create_name_query` | For CONNECT, `%` cannot even reach `$host` (request-line charset, see above); `'` and other sub-delims can, inside an IPv6 literal (→ `invalid IPv6 address`, never resolved) or via a non-CONNECT `Host` header (`validate_host` :2348-2363 admits them). `ngx_resolver_create_name_query()` src/core/ngx_resolver.c:3728-3757 copies bytes verbatim and only encodes label lengths, rejecting empty labels and labels > 255 (:3742-3743, :3753-3754); `..` is already rejected by `validate_host` (:2339-2341), a trailing dot is stripped by `ngx_resolve_name()` (:442-443), the buffer is sized from `name->len` (:3673-3678). No memory-safety issue; the DNS server just gets an odd label. | not exercised (static) | **Consistent-by-design** (bounded; matches Agent B's reading). |

### 1.7 New candidates

**HTTP-G-1 (Low / robustness) — `CONNECT host:0` yields 500 instead of 400.**
`ngx_http_validate_host()` accepts port 0 (only the upper bound is checked, src/http/ngx_http_request.c:2432), `$request_port` is empty for 0 (ngx_http_variables.c:1571), `ngx_http_tunnel_eval()` fails in `ngx_parse_url()` and the handler returns `NGX_HTTP_INTERNAL_SERVER_ERROR` (ngx_http_tunnel_module.c:199-201). Verified: `CONNECT 127.0.0.1:0 HTTP/1.1` → `HTTP/1.1 500 Internal Server Error`, log `[info] invalid port in upstream "127.0.0.1:"`. Client-triggerable 500 (log noise, wrong status class); no other impact. Fix idea: in `ngx_http_process_request_header()`'s CONNECT branch (:2098-2111) reject `r->port == 0` with 400, mirroring the "no port" case. Not patched here (out of the minimal scope).

**HTTP-G-2 (Informational / UBSan nit) — tunnel upstream error lines format `{0, NULL}` strings.**
UBSan reported `src/core/ngx_string.c:586:19: runtime error: null pointer passed as argument 2` on the `[::1]` probe. Cause: `ngx_http_log_error_handler()` prints `", upstream: \"%V%V%s%V\""` with `&u->schema` and `&u->uri` (src/http/ngx_http_request.c:4214-4216); `ngx_http_upstream_create()` zeroes both and the tunnel module never sets `u->schema` (every other upstream module does: fastcgi :735, scgi :532, uwsgi :708-714, grpc :595-601, memcached :203) and, like fastcgi/scgi/uwsgi/grpc, never sets `u->uri`. `%V` with `len == 0` ends in `ngx_cpymem(buf, NULL, 0)`. Harmless in practice (zero-length memcpy), same class as CFG-F-1. Reproduced once per failing tunnel connect; `GET /` and `CONNECT` without `Host` do not trigger it. Suggested fix (not applied): `ngx_str_set(&u->schema, "tunnel://");` in `ngx_http_tunnel_handler()` for parity, and/or guard `len == 0` in `ngx_sprintf_str()` for the generic `u->uri` case.

Nothing else in the tree shares HTTP-1's root cause. HTTP-2 (server-wide `allow_connect`, tunnel module :463-465) has no sibling: `allow_connect` is only set there (`grep -rn allow_connect src` → tunnel module and the gate at ngx_http_request.c:2099).

---

## Part 2 — Remediation

### 2.1 Diff 1 (implemented): config-time warning when `tunnel_pass` sits where CONNECT can never reach it (HTTP-F-1 / HTTP-2)

What is cheaply checkable at config time, from `ngx_http_core_loc_conf_t` (src/http/ngx_http_core_module.h:314-331) inside `ngx_http_tunnel_pass()`:

* `name.len == 0` → the directive is at `server {}` level (`tunnel_pass` allows `NGX_HTTP_SRV_CONF`, tunnel module :54-56); CONNECT falls through to the server-level loc conf when no location matches "/" — reachable, no warning.
* `named` (`@name`, core :3297-3298) → reachable through `try_files`/`error_page` internal redirects from "/" — no warning.
* `predicate` (this fork's `location $var {}`, core :3279-3291) → evaluated at runtime — cannot decide, no warning.
* `regex` (core :3225-3236, :3259-3277) → run `ngx_regex_exec(clcf->regex->regex, "/", NULL, 0)` once at config time (same call shape as `ngx_regex_exec_array()`, src/core/ngx_regex.c:476; PCRE2 bumps ovecsize 0 to 1 and the capture copy loop is a no-op, :437-444). `NGX_REGEX_NO_MATCHED` → warn.
* otherwise prefix / exact / `^~` (core :3215-3223, :3247-3257, :3293-3300): reachable iff `name` is exactly `"/"`. This covers `if {}` and `limit_except {}` blocks too, because both copy the parent's name (`clcf->name = pclcf->name`, src/http/modules/ngx_http_rewrite_module.c:583 and ngx_http_core_module.c:4858) — `prev_location` is `#if 0` (core :3309-3311, header :461-463) so the name is the only parent information available.

Why "/" is the only reachable URI: ngx_http_parse.c:737-740 pins `uri_start/uri_end` to the "/" of "HTTP/1.1" for CONNECT, so `ngx_http_core_find_static_location()` (core :1545-1620) can only hit a node whose name is a prefix of "/" (i.e. "/" itself, exact or inclusive), and regex locations are then tried against the literal "/" (core :1481-1506).

Stated limitation: the check is local to one directive. It cannot see that *another* location shadows the one holding `tunnel_pass` (e.g. `location = / { return 200; }` next to `location / { tunnel_pass; }`, or an earlier regex location that also matches "/"), nor that an `if` condition inside `location /` never holds for CONNECT. Detecting that would require walking the server's location tree in a postconfiguration handler; not worth it for a warning.

Config-test matrix (real output; `gh-http1/tcheck/nginx.conf`):

```
==== orig
nginx: the configuration file nginx.conf syntax is ok
nginx: configuration file nginx.conf test is successful
==== patched
nginx: [warn] "tunnel_pass" in location "/x" cannot be reached by CONNECT requests, which always have URI "/" and are routed to the location matching "/" in nginx.conf:11
nginx: [warn] "tunnel_pass" in location "/proxy/" cannot be reached by CONNECT requests, which always have URI "/" and are routed to the location matching "/" in nginx.conf:12
nginx: [warn] "tunnel_pass" in location "^/api" cannot be reached by CONNECT requests, which always have URI "/" and are routed to the location matching "/" in nginx.conf:13
nginx: [warn] "tunnel_pass" in location "/x" cannot be reached by CONNECT requests, which always have URI "/" and are routed to the location matching "/" in nginx.conf:14
nginx: the configuration file nginx.conf syntax is ok
nginx: configuration file nginx.conf test is successful
```
Lines 5-10 and 15 of that file (`location /`, `location = /`, server level, `if` inside `/`, `location ~ ^/`, `location @t`, `location ^~ /`) produce no warning; lines 11-14 (`= /x`, `/proxy/`, `~ ^/api`, `if` inside `/x`) each produce exactly one. (A `limit_except { tunnel_pass; }` line was removed from the matrix because the directive's flags do not include `NGX_HTTP_LMT_CONF`: it is an `[emerg]` on both binaries, i.e. not a case the warning needs to handle; the `lmt_excpt` inheritance at tunnel module :432-436 only copies a parent's `tunnel_pass`.)

### 2.2 Proposed diff 2 (assessed, **not implemented**): warn when the default `$host:$request_port` target is used without access/auth handlers

What would be needed and why it is not clean:

* Timing: inside `ngx_http_tunnel_pass()` the location's `allow`/`deny`/`auth_basic`/`auth_request` directives may simply not have been parsed yet (they can follow `tunnel_pass`), so the check must live in `ngx_http_tunnel_merge_loc_conf()` or a postconfiguration walk. Merge order works out (modules merge in `ngx_modules[]` order with the server/location loop inside `ngx_http_merge_servers()`, src/http/ngx_http.c:564-600; access/auth_basic/auth_request have indices 141-143 and the tunnel module 159 in `build-asan/ngx_modules.c`, so their loc confs are final by then), and `ngx_http_conf_get_module_loc_conf()` resolves correctly during merge because `ctx->loc_conf = clcf->loc_conf` is set per location (ngx_http.c:649).
* Data: the structs are private to their modules — `ngx_http_access_loc_conf_t { rules, rules6, rules_un }` (src/http/modules/ngx_http_access_module.c:38-45), `ngx_http_auth_basic_loc_conf_t { realm, user_file }` (:18-20), `ngx_http_auth_request_conf_t { uri, vars }` (:14-16). The tunnel module would have to duplicate those layouts or the modules would have to export accessors; the access and auth_basic modules are also optional (`--without-http_access_module`, `--without-http_auth_basic_module`) and auth_request is opt-in, so the lookups need `#if` guards and `ngx_http_access_module.ctx_index` indirection.
* Semantics: `satisfy`, `allow all` plus `deny`, inherited server-level rules, third-party access modules (njs `js_access`, Lua, auth_jwt, auth_ldap), the `if ($x) { return 403; }` pattern below, `limit_except`, and client-certificate gating are all legitimate controls that the check cannot see. The warning would fire for correctly hardened configurations and be silenced by `allow all;`, which is exactly the wrong incentive.

Conclusion: not cheap, not reliable, and a false warning on a correct config is worse than none. Replaced by 2.3.

### 2.3 Diff 3 alternative (implemented as documentation + reference configuration, proven in Part 3)

Hardening note for the module documentation (there is none in-tree; `docs/xml/nginx/changes.xml` is the only mention):

> `tunnel_pass` without an argument (or with `$host:$request_port`) makes the CONNECT client choose the destination host **and** port. nginx applies no built-in destination or port restriction (unlike Apache `AllowCONNECT`, default 443/563, or Squid `Safe_ports`/`SSL_ports`). Always pair it with at least one of: `auth_basic` (nginx answers 407 for CONNECT), `allow`/`deny`, or a destination allow-list. Write allow-lists against `$host` (normalised: lower-case, trailing dot removed, port stripped) and `$request_port`, as an **allow**-list — deny-lists on `127.0.0.1` are bypassed with `localhost`, `[::1]`, `[::ffff:127.0.0.1]` or any DNS name that resolves to an internal address. A fixed target (`tunnel_pass host:port;` or an `upstream`) ignores the client authority entirely and needs no destination filter.

Reference configuration (the regression test uses it verbatim, with the backend port standing in for 443):

```nginx
map "$host:$request_port" $tunnel_allowed {
    default                              0;
    "~^allowed\.example:443$"            1;   # one line per permitted host:port
}

server {
    listen 443;            # or whatever the proxy listener is
    location / {           # CONNECT always arrives with URI "/"
        if ($tunnel_allowed = 0) {
            return 403;
        }
        tunnel_pass;       # == tunnel_pass $host:$request_port;
    }
}
```
Observed with this config (Part 3, both binaries): `CONNECT 127.0.0.1:<backend>`, `127.0.0.1:443`, `localhost:443`, `[::1]:443`, `allowed.example:<other port>` → `403 Forbidden`; `allowed.example:<backend>` and `ALLOWED.EXAMPLE.:<backend>` → `200 OK` and the request went through the tunnel (`SEE-THIS`).

### 2.4 Sketch: a `tunnel_allow_ports` directive (not implemented)

Shape: `tunnel_allow_ports 443 563;` (`NGX_HTTP_LOC_CONF|NGX_CONF_1MORE`, loc conf `ngx_array_t *allow_ports` of `in_port_t`, merged with `ngx_conf_merge_ptr_value`), checked in `ngx_http_tunnel_eval()` right after `ngx_parse_url()`: if the array is set and `url.port` is not in it, return a distinct code so `ngx_http_tunnel_handler()` returns `NGX_HTTP_FORBIDDEN` instead of 500. About 40 lines, cheap, and it would give nginx an `AllowCONNECT` equivalent with a sensible default of 443 for the variable form.

Why it was not implemented here: (a) a port allow-list alone does not close HTTP-1 — `127.0.0.1:443` and `169.254.169.254:443` remain reachable, so it would invite a false sense of safety unless paired with a host filter; (b) a *host* allow-list needs post-resolution address matching (the client can name any DNS label), and the upstream machinery has no hook between `ngx_http_upstream_resolve_handler()` and `ngx_http_upstream_connect()` (ngx_http_upstream.c:742-835); adding one is a design change that should be discussed upstream rather than slipped into a hardening patch; (c) the `map` + `if/return` idiom in 2.3 already expresses both dimensions with no new surface, and the official tests already document `auth_basic` as the intended control. If upstream wants a built-in, the right shape is `tunnel_allow host:port ...` evaluated against resolved addresses, with `443` as the default port set for the variable form.

### 2.5 Official tests against the patched binary

`TEST_NGINX_GLOBALS="user root;"`, `TEST_NGINX_BINARY=.../gh-http1/nginx-{orig,patched}`, `ASAN_OPTIONS=detect_leaks=0` (real output, `gh-http1/official-tests.log`):

```
==== binary: nginx-orig
tunnel.t ................ ok
tunnel_auth_basic.t ..... ok
tunnel_next_upstream.t .. ok
All tests successful.
Files=3, Tests=34,  8 wallclock secs ( 0.02 usr  0.01 sys +  0.32 cusr  0.21 csys =  0.56 CPU)
Result: PASS
==== binary: nginx-patched
tunnel.t ................ ok
tunnel_auth_basic.t ..... ok
tunnel_next_upstream.t .. ok
All tests successful.
Files=3, Tests=34,  8 wallclock secs ( 0.02 usr  0.01 sys +  0.34 cusr  0.19 csys =  0.56 CPU)
Result: PASS
```
`tunnel.t` exercises `tunnel_pass` inside `if` within `location /` and at server level, i.e. two of the "must not warn" shapes; it passes without warnings on the patched binary.

---

## Part 3 — Regression test

File: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/patches/HTTP-1-regression.t`. nginx-tests style; copy it into the nginx-tests directory and run with `prove -I lib`.

* (a) writes `warn.conf` (`location / { return 200; } location = /x { tunnel_pass; }`) and `nowarn.conf` (`location / { tunnel_pass; }`), runs `$NGINX -t -p <testdir> -c <conf>` and asserts the `[warn] "tunnel_pass" in location "/x" cannot be reached` line is present for the first and absent for the second (the `-t` output carries the `PID#TID:` prefix because the harness's `logs/` directory does not exist, hence the optional group in the regex).
* (b) runs the reference configuration from 2.3 on port 19280 with a DNS stub (`allowed.example` → 127.0.0.1) on 19290/udp and a `SEE-THIS` backend on 19281 (ports via `%%PORT_192xx%%`, the harness falls back inside 19000-19499 only if taken).

Real output (`gh-http1/regression-run.log`):

```
==== binary: nginx-orig
gh_http1_regression.t ..
1..13
not ok 1 - warning for tunnel_pass in location = /x
ok 2 - warn.conf still valid
ok 3 - no warning for tunnel_pass in location /
ok 4 - nowarn.conf valid
ok 5 - loopback IP blocked
ok 6 - loopback IP on allowed port blocked
ok 7 - localhost blocked
ok 8 - IPv6 loopback literal blocked
ok 9 - allowed host, non-allowed port blocked
ok 10 - allowed host and port tunnelled
ok 11 - allowed host, case and trailing dot normalised
ok 12 - no alerts
ok 13 - no sanitizer errors
Dubious, test returned 1 (wstat 256, 0x100)
Failed 1/13 subtests
==== binary: nginx-patched
gh_http1_regression.t ..
1..13
ok 1 - warning for tunnel_pass in location = /x
ok 2 - warn.conf still valid
ok 3 - no warning for tunnel_pass in location /
ok 4 - nowarn.conf valid
ok 5 - loopback IP blocked
ok 6 - loopback IP on allowed port blocked
ok 7 - localhost blocked
ok 8 - IPv6 loopback literal blocked
ok 9 - allowed host, non-allowed port blocked
ok 10 - allowed host and port tunnelled
ok 11 - allowed host, case and trailing dot normalised
ok 12 - no alerts
ok 13 - no sanitizer errors
ok
All tests successful.
Result: PASS
```
Exactly as required: (a) fails only on the unpatched binary (test 1); (b) passes on both; the harness's own "no alerts" / "no sanitizer errors" checks pass on both.

---

## Artifacts

* Report: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/GH-HTTP-1.md`
* Diff: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/patches/HTTP-1.diff` (`patch -p1 --dry-run` against a pristine copy of the file: OK)
* Regression test: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/patches/HTTP-1-regression.t`
* Work dir: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-http1/` — `src-http1/` (patched copy), `nginx-orig`, `nginx-patched`, `probe/` (Part 1.6 config, backend, client, logs), `tcheck/` (warning matrix), `official-tests.log`, `regression-run.log`, `make-orig.log`, `make-patched.log`.

## Diff 1 inline (identical to patches/HTTP-1.diff)

```diff
--- a/src/http/modules/ngx_http_tunnel_module.c
+++ b/src/http/modules/ngx_http_tunnel_module.c
@@ -33,6 +33,8 @@
 
 static char *ngx_http_tunnel_pass(ngx_conf_t *cf, ngx_command_t *cmd,
     void *conf);
+static void ngx_http_tunnel_check_location(ngx_conf_t *cf,
+    ngx_http_core_loc_conf_t *clcf);
 
 static char *ngx_http_tunnel_lowat_check(ngx_conf_t *cf, void *post, void *data);
 
@@ -458,6 +460,8 @@
 
     clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
 
+    ngx_http_tunnel_check_location(cf, clcf);
+
     clcf->handler = ngx_http_tunnel_handler;
 
     cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
@@ -508,6 +512,51 @@
 }
 
 
+/*
+ * A CONNECT request always carries the URI "/" (ngx_http_parse_request_line()
+ * pins uri_start/uri_end to the "/" of "HTTP/1.1"), so it can only be routed
+ * to a location that matches "/": the server level, a prefix or exact
+ * location "/", an "if" or "limit_except" block inside one of those (they
+ * inherit the parent's name), a regular expression location matching "/",
+ * or a named location reached through an internal redirect.  A "tunnel_pass"
+ * anywhere else is dead for CONNECT, while "allow_connect" is still enabled
+ * server-wide and CONNECT requests are handled by whatever serves "/".
+ */
+
+static void
+ngx_http_tunnel_check_location(ngx_conf_t *cf, ngx_http_core_loc_conf_t *clcf)
+{
+#if (NGX_PCRE)
+    ngx_int_t  rc;
+    ngx_str_t  slash = ngx_string("/");
+#endif
+
+    if (clcf->name.len == 0 || clcf->named || clcf->predicate) {
+        return;
+    }
+
+#if (NGX_PCRE)
+    if (clcf->regex) {
+        rc = ngx_regex_exec(clcf->regex->regex, &slash, NULL, 0);
+
+        if (rc != NGX_REGEX_NO_MATCHED) {
+            return;
+        }
+
+    } else
+#endif
+    if (clcf->name.len == 1 && clcf->name.data[0] == '/') {
+        return;
+    }
+
+    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
+                       "\"tunnel_pass\" in location \"%V\" cannot be reached "
+                       "by CONNECT requests, which always have URI \"/\" "
+                       "and are routed to the location matching \"/\"",
+                       &clcf->name);
+}
+
+
 static char *
 ngx_http_tunnel_lowat_check(ngx_conf_t *cf, void *post, void *data)
 {
```
