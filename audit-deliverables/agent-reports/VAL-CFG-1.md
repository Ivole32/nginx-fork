# VAL-CFG-1 — Independent validation of CFG-1 (Control API: no authentication)

Validator: Agent F. Non-destructive, loopback-only. Revision b38c9d8068 (1.31.8 dev).
Independent ASan+UBSan build (my own, repo untouched):
`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/val-cfg1/build/nginx`
(configured `--with-control-api --with-http_ssl_module --with-debug` + ASan/UBSan; configure.log/make.log alongside).
Test tree under `.../audit/val-cfg1/t`, loopback ports 18700 (control) / 18701-18702 (data). Repo `git status` clean (0 changes).

## Conclusion

**Design decision needing hardening + documentation — NOT a code-level vulnerability, and NOT rejected.**

Every factual claim in CFG-1 is **CONFIRMED** by independent code reading and live reproduction:
the Control API performs no authentication, authorization, peer-credential or source-address check of any
kind; it accepts any `ngx_parse_url()` listen address including TCP (no loopback restriction in code); it
serves the full verbatim configuration on `GET /1/control/config` and executes a root-process reload on
`PATCH /1/control/config`, to anyone who can `connect()`. Unix sockets are `chmod 0600` (correct).

Where I **re-scope** Agent D's framing: this is best classified as an *opt-in administrative interface whose
security model is the socket's reachability* (the same model as every comparable tool — see Severity). It is
not a parser/memory-safety bug, not default-on, and not remotely reachable unless the operator chooses a
non-loopback bind. The genuine product gaps are (a) **no audit trail** and (b) **documentation that shows
`127.0.0.1:` examples without stating that the endpoint is unauthenticated and reachable by every local
account**. On a multi-user host this is a realistic local information-disclosure + local forced-reload
primitive. On a single-admin host it is negligible.

Confidence in the facts: **High** (reproduced). Severity is a **judgment call** (I argue Low–Medium, below).

---

## Evidence per objective question

### Q1a — No authentication / authorization anywhere
Confirmed by reading the whole module and by grep. `src/os/unix/ngx_control.c`:
- `ngx_control_handle_accept()` line 470: `fd = accept(ngx_control_pollfd[0].fd, NULL, NULL);` — the peer
  `sockaddr` is passed as `NULL`, so the source address is **not even captured**, let alone checked.
- Grep for `peercred|getpeername|SO_PEER|ucred|allow|deny|auth|token|password|secret|loopback|INADDR_LOOPBACK`
  in `ngx_control.c` returns **nothing** relevant (the only `NOT_ALLOWED`/405 hits are HTTP *method* checks in
  `ngx_control_content()`, not authorization).
- `ngx_control_content()` (616-704) dispatches straight from parsed method+path to the handler. No credential
  is read; request headers and body are never consumed (the parser stops at the request line).

### Q1b — TCP allowed, no address restriction
`ngx_control_init()` (147-268): after `ngx_parse_url(&u)`, the only address validation is:
```c
#if (NGX_HAVE_UNIX_DOMAIN)
    if (u.family == AF_UNIX) { ngx_memcpy(ngx_control_unix_path, ...); }
    else if (u.no_port || u.last_port) { /* "invalid port" -> NGX_ERROR */ }
#endif
```
There is **no** check that a TCP address is loopback. `-l 0.0.0.0:PORT` or `-l <public-ip>:PORT` binds and
listens with no auth (I did **not** bind non-loopback per the brief's rules; the code path is unambiguous and
the only rejects are "no port"/"port range"). `nginx.c` `-l` handling (955-977) stores the raw argv string and
sets `ngx_control_api_enabled=1`; init happens in the **master after `ngx_daemon()`** (nginx.c 370-379), i.e.
the socket and all request servicing live in the root master process (`ngx_process_cycle.c:178-197`).

### Q1c — Exactly what is exposed
- `GET /` → `["1"]`; `GET /1` → `["control","nginx"]`; `GET /1/control` → `["processes","config"]` (endpoint listings).
- `GET /1/nginx` → version + build string.
- `GET /1/control/processes` → worker/process names, pids, exiting flag (`ngx_control_show_processes`).
- `GET /1/control/config` → **every dumped config file verbatim**, name + content, including `include`d files
  (`ngx_control_print_config` 913-944 over `ngx_cycle->config_dump`). `-l` forces config dumping on for the whole
  process (`ngx_conf_file.c:224` `|| ngx_control_api_enabled`), so the master permanently holds all config text
  in memory (also exposed in core dumps).
- `PATCH /1/control/config` → `ngx_control_reload_config` (982-1023) calls `ngx_init_cycle()` **in the master
  (root)**, swaps `ngx_cycle`, sets `r->reloaded`; `ngx_control_handle_events` returns `NGX_DONE`, and
  `ngx_process_cycle.c:181-195` then respawns workers and `SIGSHUTDOWN`s the old ones — functionally identical to
  `kill -HUP`. Reload returns captured error-log lines (file paths, directive errors) to the caller as JSON.

### Q1d — Abuse beyond disclosure + forced reload? (memory safety, buffers, fd, liveness)
I independently stress-tested the parser and connection handling; **no exploitable path beyond C/A found**:
- **Parser**: ran the official `control_api.t` (98 assertions) against *my* build → **all pass**: oversize
  request line (1048 bytes) closed, NUL in method/URI → 400, CRLF injection in URI → 400, percent/fragment/
  high-byte/UTF-8 handling, HTTP version edge cases, absolute-URI/IPv6-literal host forms, split-across-reads.
  Request line bounded by the 1024-byte `ngx_create_temp_buf`; `b->last==b->end` guard at `ngx_control_handle_read`
  returns error before overflow. No ASan/UBSan fault during the run.
- **`ngx_control_log_capture` (1025-1050)**: copies `len` bytes from the caller-supplied `buf` with `ngx_pnalloc`
  sized to exactly `len` — no fixed buffer, no truncation bug; only `<= NGX_LOG_WARN` lines stored. Sound.
- **Response building** (`ngx_json.c` length/encode pass is two-phase with `NGX_MAX_SIZE_T_VALUE` overflow guards
  on every accumulation; `ngx_data.c` handlers `ngx_pstrdup` each field into the request pool). Sound.
- **fd exhaustion at `NGX_CTRL_MAX_FD=64`**: `control_api.t` exercises the 63-connection limit + oldest-eviction
  (`ngx_control_handle_accept` 488-495) and the memmove compaction in `ngx_control_close` → pass, no crash. A
  client can tie up ≤63 control slots (DoS of the *control* socket only; data plane unaffected; self-healing via
  eviction).
- **Lost-wakeup liveness** (Agent D's low-pri note): confirmed real but liveness-only; `control_api.t`'s
  "accept queue drained / SIGIO coalesces" cases pass, so a well-behaved client is always served.
- **Reload during binary upgrade / dangling stack `log`**: Agent D's two low-pri notes stand; I did not find a
  runtime deref of the stack `ngx_log_t`, consistent with D. Operational/fragility, not a current defect.

**Net:** impact is confidentiality (full config incl. any embedded secrets) + availability/integrity
(unauthenticated forced reload) only. No RCE, no memory corruption.

### Q2 — Intent: documented? tested? is "no auth" a design decision?
- **Build gate**: `auto/options:44,228,473` (`--with-control-api`, default `NO`); `auto/modules:59-72` compiles
  `ngx_control.c` only when enabled; not on Windows. Strictly opt-in, off by default.
- **Changelog**: `docs/xml/nginx/changes.xml:312-320` — "feature: control API." in **1.31.5 (2026-09-02)**. Plus a
  1.31.7 bugfix about the control socket + perl binary upgrade (259-270). No security wording.
- **Man page** `docs/man/nginx.8:70-74, 174-194`: documents `-l addr`, a `CONTROL SOCKET` section with examples
  `-l 127.0.0.1:8888`, `-l [::1]:8888`, and `-l unix:/path/to/socket`. **It does not state the endpoint is
  unauthenticated, nor advise restricting access** (no "localhost/unix only", no security note). `-l` help text
  (`nginx.c:433`) is one line with no warning.
- **Tests** (`.../nginx-tests-dl/nginx-tests/`): `control_api.t` and `control_api_upgrade.t` bind
  **`127.0.0.1:<port>`**; `control_api_unix.t` uses a unix socket and **asserts `stat & 07777 == 0600`** plus
  socket removal on stop. The harness feature gate is `control_api => '--with-control-api'` (`lib/Test/Nginx.pm:175`).
  So TCP binding is both documented and tested; **the lack of auth is clearly an accepted design decision** — the
  tests rely on an unauthenticated endpoint, and the unix-socket test treats `0600` as *the* access control.
- **SECURITY.md**: "Data Plane vs. Control Plane" (74-82) explicitly scopes configuration/management/orchestration
  as the *control plane* and states config files are *trusted*; "Trusted Configurations" (64-73) makes operators
  responsible for securing management inputs. This is the project's stated model and it covers this interface:
  the Control API is a control-plane tool whose protection is deployment (socket reachability), by design.

### Q3 — Reproduction (my independent build, master as root, `user nobody nogroup`)
Config includes `secrets.inc` with a marker line simulating an operator secret. Started with:
`nginx -p .../val-cfg1/t -c conf/nginx.conf -l 127.0.0.1:18700` (data plane on 18701/18702).
Master runs as root; client run as **uid 65534** via `setpriv --reuid=65534 --regid=65534 --clear-groups`.

```
$ setpriv --reuid=65534 --regid=65534 --clear-groups id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)

# [1] GET /1/control/config  (as nobody)
HTTP/1.1 200 OK
Server: nginx/1.31.8
Connection: close
Content-Type: application/json
Content-Length: 984

[{"name":".../t/conf/nginx.conf","content":"user nobody nogroup;\n...include secrets.inc;\n..."},
 {"name":".../t/conf/secrets.inc",
  "content":"# VAL-CFG-1 MARKER: this included file simulates an operator secret\n
             upstream backend { server 127.0.0.1:18701; }\n
             # proxy_set_header Authorization \"Bearer SUPERSECRET-TOKEN-12345\";\n"}]
   --> full config AND the included file returned verbatim to an unprivileged user.

# [3] GET /1/nginx           -> {"version":"1.31.8","build":""}
# [2] GET /1/control/processes -> [{"name":"worker process","pid":17122,"exiting":false}]

# [5] PATCH /1/control/config (as nobody)
HTTP/1.1 200 OK ... {"logs":[]}
# worker pid before: 17122  -> after: 17148   (forced reload executed in root master)
# [7] data plane still serving: "VAL-CFG-1 ok"

# [6] POST/PUT/DELETE/HEAD /1/control/config -> 405  (method check only; GET/PATCH need no credential)
```
- **No audit trail**: the control request appears in **neither** `access.log` (only the data-plane GET is logged)
  **nor** `error.log` with any peer attribution — reload `[notice]`s name no source (the peer address is never
  captured). An operator cannot tell who read the config or triggered the reload.
- **Official suites against my build**: `control_api.t` → **98/98 PASS**; `control_api_unix.t` → **8/8 PASS**
  (independently confirms socket `0600` and removal on stop).

### Q4 — Severity (realistic) and comparison
Comparable admin interfaces are **also unauthenticated by default and rely on bind scope**:
- **HAProxy stats/admin socket** — no auth; docs say bind to a unix socket (mode/user/group) or localhost.
- **nginx `stub_status`** — no auth; guidance is `allow 127.0.0.1; deny all;`.
- **Envoy admin interface** — explicitly documented as having no access control and MUST be bound to localhost/
  a protected address; exposing it is a known operator footgun.
This endpoint is squarely in that category. Differences that *raise* concern vs. those: `GET /config` discloses
**the entire configuration including any embedded credentials**, and `127.0.0.1` is **not** a trust boundary on a
multi-user host (every local account can reach it). Differences that *lower* concern: opt-in compile + explicit
`-l`, operator-chosen bind, unix-socket option is `0600` (true per-user access control), no memory-safety/RCE.

My assessment: **Low–Medium**. Realistic worst case where deployed = local unprivileged info-disclosure of
config secrets + local unauthenticated forced reload on a shared host; or, if an operator ignores the examples
and binds non-loopback, remote unauthenticated config disclosure + reload. Not a default-reachable or
memory-corruption issue. **Confidence: High on facts; Medium on the severity label** (depends on deployment).

## Existing mitigations (verified)
- Opt-in: `--with-control-api` off by default; `-l` required; disabled in single-process mode (nginx.c 370-374).
- Unix socket path is `chmod 0600` **before** `listen()` (ngx_control.c 247-256), so the brief 0777 window
  (umask(0) in daemon) is not connectable; test asserts `0600`; socket removed on QUIT.
- Accepted control fds get `FD_CLOEXEC`; workers close all control fds (`ngx_worker_process_init` →
  `ngx_control_close_sockets`), so a compromised worker cannot reach the control socket.
- Request line hard-capped at 1024 bytes; tight parser (98-assertion suite passes); 64-fd cap with eviction.

## New candidates discovered
### CFG-F-1 (LOW / informational — benign UBSan nit, NOT a security issue)
During the **first** control-API reload after startup, UBSan reported once:
`src/core/ngx_string.c:84:5: runtime error: null pointer passed as argument 2, which is declared to never be null`
— i.e. `ngx_memcpy(dst, src->data=NULL, src->len=0)` inside `ngx_pstrdup` (ngx_string.c:75-87), reached via the
`ngx_data`/JSON render path (e.g. the empty `build` string `ngx_control_build` which has `data=NULL,len=0`, or an
empty config field). A plain `SIGHUP` did **not** trigger it, so it is tied to the control-API code path, but it
is a **zero-length** copy — harmless in practice (glibc handles `memcpy(p,NULL,0)`), no OOB, and I could **not**
reproduce it on subsequent PATCH/GET requests. Not a candidate defect; noted for completeness. A trivial
hardening would be `if (src->len) ngx_memcpy(...)` in `ngx_pstrdup`, or skip NULL-data strings in the data layer.

## Remaining uncertainty / limitations
- Could not test a genuinely remote client or a non-loopback bind (brief rules); the TCP "any address, no
  loopback check" claim rests on reading `ngx_control_init` (unambiguous) + the local-unprivileged repro.
- Did not re-drive the USR2 binary-upgrade handoff (`control_api_upgrade.t` is gated behind `TEST_NGINX_UNSAFE`);
  I relied on code reading + Agent D for that path.
- CFG-F-1 UBSan nit was observed once and not reproduced; I could not pin the exact field with certainty.
- Severity is deployment-dependent; I give a range rather than a single number.
