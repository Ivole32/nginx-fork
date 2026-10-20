# GH-CFG-1 — Variant analysis (Agent G) and remediation + regression test (Agent H) for CFG-1

Parent finding: CFG-1 (Control API `-l addr` has no authentication; validated as "design decision needing
hardening + documentation", Medium on multi-user hosts). Revision b38c9d8068 (1.31.8 dev). Repository untouched
(`git status --short | wc -l` = 0 before and after). All work under
`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-cfg1/` (= `$G` below), loopback ports 19100-19131.

Builds (both my own, ASan+UBSan, `--with-control-api --with-debug`, see `$G/configure.log`, `$G/make*.log`):
- `$G/nginx-unpatched` — pristine copy of the repo (`$G/src-cfg1` before patching)
- `$G/nginx-patched`   — same copy with `CFG-1.diff` + `CFG-F-1.diff` applied

Deliverables:
- this report: `$A/GH-CFG-1.md`
- `$A/patches/CFG-1.diff` (ngx_control.c + docs/man/nginx.8), `$A/patches/CFG-F-1.diff` (one-liner)
- `$A/patches/CFG-1-regression.t` (nginx-tests style)

---

## Part 1 — Variant analysis

Pattern searched: *"reachability is the only authorization for a management interface, and the management
action runs in the root master"*. Verdicts below; everything cites the unmodified repository.

### (a) Other sockets serviced by the master; master/worker channel

**Grep result.** `accept(|recv(|recvmsg(|poll(` in `src/os/unix` and `src/core` outside `ngx_control.c` hits only
`src/os/unix/ngx_channel.c:128` (`recvmsg` in `ngx_read_channel`) and `src/core/ngx_resolver.c:1692` (resolver
`ngx_recv`, worker-side, upstream-trusted DNS path, out of scope). The control socket is the **only** socket the
master accepts connections on.

**Channel direction.** `ngx_read_channel()` has exactly one caller, `ngx_channel_handler()`
(`src/os/unix/ngx_process_cycle.c:1053`), and that handler is registered exactly once, in
`ngx_worker_process_init()` (`ngx_process_cycle.c:963`, on `ngx_channel` = the worker's own `channel[1]`).
The master never reads from any channel; it only writes (`ngx_pass_open_channel` :425, `ngx_signal_worker_processes`
:471-479, `ngx_reap_children` :565). Therefore **a compromised worker cannot send `NGX_CMD_*` to the master** —
there is no receiver. `NGX_CMD_QUIT/TERMINATE/REOPEN/OPEN_CHANNEL/CLOSE_CHANNEL` (:1082-1104) are only ever
interpreted by workers.

What a compromised worker *can* do: it keeps `ngx_processes[n].channel[0]` (write ends to its siblings; only
`channel[1]` of siblings and its own `channel[0]` are closed, :940-955) and can therefore send `NGX_CMD_QUIT`/
`NGX_CMD_TERMINATE` to **sibling workers**, or an `NGX_CMD_OPEN_CHANNEL` with an attacker-chosen fd/slot/pid that the
sibling stores into `ngx_processes[ch.slot]` without bounds checking `ch.slot` against `ngx_last_process`
(`:1094-1102` — `ngx_processes[ch.slot].pid = ch.pid;`). All workers run as the same unprivileged uid, so a
compromised worker can already `kill()` its siblings or `ptrace` them (subject to Yama); the channel adds no
privilege. The unchecked `ch.slot` write is bounded by `NGX_MAX_PROCESSES` only if `ch.slot` is small; a sibling
can send any `ngx_int_t`. **Verdict: not a variant of CFG-1** (no master exposure, no privilege boundary crossed:
sender and receiver share uid). Noted as **CFG-G-1 (Low, hardening-only)**: `ngx_channel_handler` trusts
`ch.slot` from a same-uid peer; a `ch.slot >= NGX_MAX_PROCESSES` write is an OOB store in the *receiving worker*,
but the only sender with the write end is another worker of the same uid, which already has equal or greater
power over the receiver. Upstream behaviour, unchanged for many years; mention only.

### (b) Binary-upgrade handoff `NGINX_CTRL` — when is the environment trusted?

Trace (unmodified source):
1. `src/core/nginx.c:293` — `ngx_control_preinit()` runs in `main()` **before** `ngx_init_cycle()` and simply
   caches `getenv("NGINX_CTRL")` (`ngx_control.c:134-143`); nothing is acted on.
2. `nginx.c:370-379` — `ngx_control_init(ngx_control_addr)` is called only after daemonising; it returns
   `NGX_OK` immediately when `addr == NULL` (`ngx_control.c:153-155`), i.e. **when `-l` was not given the
   environment is never consulted**. Verified live: `NGINX_CTRL=99 nginx` (no `-l`) → no control socket, 0
   control lines in the log.
3. With `-l`, `ngx_control_inherit()` (`:401-431`) parses the env value with `ngx_atoi` and does
   `fcntl(fd, F_SETOWN, ngx_pid)`; on failure it logs `[alert]` and returns `NGX_ERROR`, and `ngx_control_init`
   then **falls through to creating a fresh socket** (`:192-195` only tests `== NGX_OK`). Verified live:
   `NGINX_CTRL=99 nginx -l 127.0.0.1:19130` → `[alert] control: fcntl(F_SETOWN) failed (9: Bad file descriptor)`
   followed by a working freshly-bound control socket (`GET /1` → 200).
4. The env is **produced** only by `ngx_exec_new_binary()` (`nginx.c:777`, `ngx_control_handoff()`
   `ngx_control.c:298-310`) in the old master (root), and consumed by the new master it execs.

Who can set `NGINX_CTRL` for a root master? Only the party that executes the nginx binary with that environment
— which is the same party that controls `argv` (`-l`, `-c`, `-g`, `-p`) and therefore already controls the config
and the control address. This is exactly the trust model of the pre-existing `NGINX` listen-fd inheritance
(`nginx.c:488-537`, `ngx_add_inherited_sockets`), which likewise adopts any fd number from the environment. If an
"attacker-owned fd" (e.g. a socket the invoker created) is adopted, the invoker merely gets a control socket they
could have asked for with `-l` anyway. Limitations worth noting (not vulnerabilities): the inherited fd is not
validated to be a listening stream socket matching the `-l` address, `FIOASYNC` is not re-applied (only
`F_SETOWN`), and `NGINX_CTRL` is not scrubbed from the new master's environ (it is only used for the exec env,
`ngx_set_environment` builds a fresh env from `env` directives/`TZ`, `nginx.c:542-630`; the new master's own
environ keeps the variable but `-l` + `getppid()` logic in `ngx_control_uninit` `:271-284` handles ownership of
the socket path). **Verdict: not a variant; same trust boundary as `NGINX=` listen inheritance.**

### (c) Does the forced config dump leak through other channels?

`src/core/ngx_conf_file.c:222-233`: the dump buffer is added when `ngx_dump_config` (`-T`) **or**
`ngx_control_api_enabled` **or** `NGX_DEBUG` (`|| 1`) — i.e. **every `--with-debug` build already keeps the full
configuration text in `cycle->pool` permanently**, with or without `-l`. The dump lives in `cycle->config_dump`
(`ngx_cycle.c:139`), allocated from the cycle pool, and is never freed after parsing; workers inherit it through
`fork()`.
- *Core dumps*: a worker core (`rlimit_core`/`working_directory`, `PR_SET_DUMPABLE` at
  `ngx_process_cycle.c:895-899`) therefore contains the raw config text. The core file is created by the kernel
  owned by the worker uid, 0600; the worker uid already has the parsed configuration (with all secrets) in the
  same memory image. No new boundary. Master cores are root-only.
- */proc*: `/proc/<worker>/mem` is readable by the worker uid (Yama permitting) — same argument.
- *`-T`*: `nginx -T` prints the dump to stdout of the invoking user, who must already be able to open the config
  files (nginx opens them with the invoker's credentials; the binary is not setuid). No bypass.
**Verdict: not a variant.** The only new exposure created by `-l` is the one already in CFG-1 (serving the dump
over the socket). Side note for operators: the dump buffers mean a *worker* memory-disclosure bug would reveal
config text verbatim in debug or `-l` builds; parsed secrets are in worker memory regardless.

### (d) Comparison with `stub_status` and similar endpoints

`src/http/modules/ngx_http_stub_status_module.c:84-130`: GET/HEAD only (`:92`), returns seven connection
counters (`ngx_stat_*`), nothing configuration-related. It is **not enabled by default** (needs the `stub_status`
directive in a `location`), and because it is an ordinary HTTP content handler it sits **behind the full access
phase** (`allow`/`deny`, `auth_basic`, `auth_request`, `satisfy`, TLS client certs), i.e. the operator has
standard tools to restrict it. There is no other status/API module in this tree (`ls src/http/modules | grep
-i "api\|status"` → only stub_status; none in `src/stream`). The Control API differs in all three respects:
far more sensitive data (full config), a mutating action (reload), and **no access-control hook at all** since
it bypasses the HTTP stack and runs in the master. **Verdict: contrast only; confirms CFG-1's severity reasoning.**

### (e) CFG-F-1 — exact caller of `ngx_memcpy(dst, NULL, 0)` in `ngx_pstrdup`

**Reproduced and pinpointed** (unpatched build, UBSan output goes to error.log because nginx dup2()s stderr to it):
- Fresh process, requests `GET /1/control/processes`, `GET /1/control/config`, `PATCH /1/control/config`,
  `GET /1/control`, `GET /1` → **0** `runtime error` lines.
- Fresh process, single `GET /1/nginx` → **1** line:
  `src/core/ngx_string.c:84:5: runtime error: null pointer passed as argument 2, which is declared to never be null`
- gdb, breakpoint on `__ubsan_handle_nonnull_arg`:
  ```
  #1 ngx_pstrdup (pool=..., src=<ngx_control_build>) at src/core/ngx_string.c:84
  #2 ngx_data_string_handler (...) at src/core/ngx_data.c:180
  #3 ngx_data_obj_handler (...) at src/core/ngx_data.c:77
  #4 ngx_control_show_version (r=...) at src/os/unix/ngx_control.c:903
  #5 ngx_control_content (r=...) at src/os/unix/ngx_control.c:660
  #6 ngx_control_handle_read / #7 ngx_control_handle_events / #8 ngx_master_process_cycle (ngx_process_cycle.c:181)
  ```
  Root cause: `src/os/unix/ngx_control.c:86-90` — when the build was configured without `--build=`, `NGX_BUILD`
  is undefined and `static ngx_str_t ngx_control_build;` is `{len=0, data=NULL}`; `ngx_data_string_handler`
  (`ngx_data.c:165-185`) calls `ngx_pstrdup(pool, src)` which does `ngx_memcpy(dst, src->data, src->len)` =
  `memcpy(dst, NULL, 0)`. Not the log capture (stack buffer, `len>0`), not `ngx_data_struct_str_handler`
  (process names and dump names are non-empty, dump buffers have non-NULL `pos`).
- Why the validator saw it "once, on the first reload": libubsan reports each check *location* only once per
  process (the second `GET /1/nginx` in the same process printed nothing in my run), and `control_api.t` issues
  `GET /nginx` as its very first request; the line simply landed next to the first reload in the log.
- **UB?** Yes, technically: C11 7.24.1p2 requires pointer arguments to be valid even when `n == 0`, and 7.1.4p1
  makes a null pointer an invalid argument. (C2y adopted N3322, which makes zero-length `memcpy` with null
  pointers defined, so this will stop being UB in a future standard; glibc already tolerates it.) No practical
  effect: zero bytes are copied, `ngx_pnalloc(pool, 0)` returns a valid pointer.
- **Does nginx guard elsewhere?** Not in the copy helpers: `ngx_memcpy`/`ngx_cpymem` are plain `memcpy` macros
  (`src/core/ngx_string.h:106-107`) or, with `NGX_MEMCPY_LIMIT`, a wrapper that only checks the size
  (`ngx_string.c:2120-2128`). `ngx_cpystrn` does guard `n == 0` (`ngx_string.c:1227` area: `if (n == 0) return dst;`).
  So the idiom "zero-length copy from NULL" is tolerated throughout nginx; this is an isolated UBSan nit.
- **Fix (CFG-F-1.diff, one line, at the source):** initialise the fallback as `ngx_string("")` so `data` is
  non-NULL. Alternative (more general, touches core): `if (src->len) ngx_memcpy(...)` in `ngx_pstrdup`. I chose
  the local fix. Verified: patched build, two `GET /1/nginx` in a fresh process → 0 `runtime error` lines,
  response unchanged (`{"version":"1.31.8","build":""}`).

### Variant summary

| Item | Verdict |
|---|---|
| (a) other master sockets | none besides control socket; master never reads channels → not a variant. CFG-G-1 (Low): unchecked `ch.slot` in worker `ngx_channel_handler`, same-uid sender only |
| (b) `NGINX_CTRL` env | consumed only with `-l`, invalid values ignored with alert, same trust as `NGINX=`; not a variant |
| (c) dump via core/proc/-T | no new boundary (debug builds always dump; worker uid already holds secrets); not a variant |
| (d) stub_status | opt-in, counters only, behind HTTP access phase; contrast only |
| (e) CFG-F-1 | pinpointed to `ngx_control_build` NULL data via `GET /1/nginx`; technically UB, harmless; one-line fix |

---

## Part 2 — Remediation (implemented on the copy, `$A/patches/CFG-1.diff`)

Design goal: smallest diff that (1) tells operators the truth, (2) makes every use of the interface attributable,
(3) nudges away from the one deployment that is actually dangerous (non-loopback TCP), while changing **no**
protocol behaviour so existing clients and tests keep working.

### Change 1 — documentation (`docs/man/nginx.8`, CONTROL SOCKET)
Adds a paragraph stating that the socket is unauthenticated, that any process able to connect can read the whole
configuration (including includes) and reload, recommends a UNIX-domain socket (mode 0600, owned by the invoking
user) or loopback on a host where every local account is trusted, says non-loopback needs host firewalling and is
warned about, and documents the audit log line. *Root cause?* Documentation addresses the "operator did not know"
half of the root cause; it does not change the security model. Compatibility: n/a. Performance: n/a.

### Change 2 — audit logging with peer attribution (`src/os/unix/ngx_control.c`)
- `ngx_control_handle_accept()`: `accept()` now captures the peer address (`&sa.sockaddr, &socklen`) instead of
  discarding it, and `ngx_control_set_peer()` formats it once per connection into a fixed buffer in
  `ngx_control_request_t` (`peer[NGX_CTRL_PEER_LEN]`, `peer_len`; the struct is memmoved on close, so inline
  storage is used, no pool pointer). TCP: `ngx_sock_ntop(..., port=1)` → `127.0.0.1:47716`. UNIX: on Linux
  `getsockopt(SO_PEERCRED)` (guarded by `#ifdef SO_PEERCRED`) → `unix uid:0 gid:0 pid:31499`; other platforms
  log `unix`.
- `ngx_control_send_response()` (the single choke point every response passes through, including 400/404/405
  and the post-reload 200/422): one `ngx_log_error(NGX_LOG_NOTICE, ...)` line:
  `control: client <peer>, "<METHOD> <path>" <status>`. Method is `GET`/`PATCH`/`-` (unparsed); path is `-`
  when the parser rejected the request before the path was complete. The path is logged verbatim only after
  the parser accepted it: `sw_uri` rejects every byte `< 0x20`, `0x7f`, `%`, `#`, `+`, `.` (`ngx_control.c:1330-1350`),
  so CR/LF injection into the log is impossible; this matches how nginx logs raw request lines elsewhere.
*Root cause?* Mitigation: it does not add authorization, but it converts an invisible action into an attributable
one (uid/pid for unix sockets is a strong attribution; for TCP it is source IP:port, which on loopback identifies
only the host — another reason the docs recommend unix sockets). Compatibility: wire protocol unchanged;
`control_api.t` (98) and `control_api_unix.t` (8) pass (see below). Operators must run `error_log ... notice` (or
lower) to see the lines, the same level as nginx's own reload/startup notices. Performance: one `getsockopt` and
one log line per control connection; nil for the data plane.

### Change 3 — warning for non-loopback TCP bind (`ngx_control_init`)
`ngx_control_loopback()` classifies the parsed `-l` address: `127.0.0.0/8`, `::1`, or `unix:` → fine; anything
else (including `0.0.0.0`, `::`, and real interface addresses) →
`[warn] control: listening on non-loopback address "<addr>" without authentication`, emitted **before** socket
creation/inherit so it is logged even if `bind()` later fails. I deliberately made this a **warning, not an
error**: an outright refusal would break legitimate container/VM deployments where the control address is
reached through a firewalled private network and would need a new override flag (more surface, more docs); a
warning is the established nginx idiom for insecure-but-allowed settings. *Root cause?* Mitigation/guidance only.
Compatibility: no behavioural change for loopback/unix (tests use those), one extra log line otherwise.
Performance: nil (startup only).

### Not done (documented proposals only)
- Real authorization: an `allow uid`/token scheme or a `--control-token` would change the model and the test
  suite; out of scope for "minimal".
- Scrubbing `NGINX_CTRL` from the new master's environ and validating that the inherited fd is a listening
  socket (variant (b) notes) — robustness, not security.
- CFG-G-1: bounds-check `ch.slot < NGX_MAX_PROCESSES` in `ngx_channel_handler` (one `if`), hardening only.

### Verification of Change 2/3 outputs (real, patched build)
TCP (`$G/t4`, `error_log ... notice`):
```
2026/10/20 22:17:54 [notice] 31340#0: control: client 127.0.0.1:47716, "GET /1/nginx" 200
2026/10/20 22:17:54 [notice] 31340#0: control: client 127.0.0.1:47728, "GET /1/nginx" 200
```
UNIX socket (`$G/t5`, `-l unix:ctrl.sock`, socket `srw------- root root`):
```
2026/10/20 22:18:53 [notice] 31494#0: control: client unix uid:0 gid:0 pid:31499, "GET /1/control/config" 200
2026/10/20 22:18:53 [notice] 31494#0: control: client unix uid:0 gid:0 pid:31504, "PATCH /1/control/config" 200
```
Non-loopback (from the regression run, `-l 192.0.2.1:19100`, RFC 5737 TEST-NET so `bind()` cannot succeed):
```
2026/10/20 22:16:35 [warn] 31181#0: control: listening on non-loopback address "192.0.2.1:19100" without authentication
2026/10/20 22:16:35 [emerg] 31181#0: control: bind() failed (99: Cannot assign requested address)
```
Official suites against the patched binary (`TEST_NGINX_GLOBALS="user root;"`):
```
control_api.t ....... ok
control_api_unix.t .. ok
All tests successful.
Files=2, Tests=106, 10 wallclock secs
Result: PASS
```
Build: no compiler warnings (`grep -c warning: make-patched*.log` → 0).

---

## Part 3 — Regression test (`$A/patches/CFG-1-regression.t`)

nginx-tests style, 14 planned assertions + the harness's automatic "no alerts"/"no sanitizer errors":
(a) five TCP requests (200/200/404/405/400) and the matching audit lines incl. `"- /" 405` (unparsed method)
and `"GET -" 400` (rejected URI); unix socket request with audit line asserting `uid:$<` and `pid:$$` of the
test process via SO_PEERCRED; (b) non-loopback `-l 192.0.2.1:<port>` run via `system()` with `-e error.log` →
expects the `[warn]` line and the `bind() failed` emerg (so nothing reachable is ever opened).

Run as: `cd <nginx-tests>; TEST_NGINX_GLOBALS="user root;" TEST_NGINX_BINARY=<bin> prove -v -I lib $A/patches/CFG-1-regression.t`

**Unpatched** (`$G/nginx-unpatched`, output `$G/regression-unpatched.txt`):
```
ok 1 - tcp get ... ok 5 - tcp bad request
not ok 6 - audit get
not ok 7 - audit reload
not ok 8 - audit not found
not ok 9 - audit unknown method
not ok 10 - audit bad request
ok 11 - unix get
not ok 12 - audit unix peer credentials
not ok 13 - non-loopback warning
ok 14 - non-loopback bind not possible here
ok 15 - no alerts
ok 16 - no sanitizer errors
Failed 7/16 subtests
```
**Patched** (`$G/nginx-patched`, output `$G/regression-patched.txt`):
```
ok 1 .. ok 16   (incl. 6-10 audit lines, 12 unix peer credentials, 13 non-loopback warning)
All tests successful.  Files=1, Tests=16  Result: PASS
```

---

## Diffs

### CFG-1.diff
```diff
--- a/src/os/unix/ngx_control.c
+++ b/src/os/unix/ngx_control.c
@@ -24,6 +24,9 @@
 
 #define NGX_CTRL_ENV             "NGINX_CTRL"
 
+/* "unix uid:N gid:N pid:N" or a socket address with port */
+#define NGX_CTRL_PEER_LEN        (NGX_SOCKADDR_STRLEN + 64)
+
 
 typedef struct {
     ngx_fd_t      fd;
@@ -38,6 +41,9 @@
     ngx_chain_t  *out;
 
     ngx_uint_t    reloaded;
+
+    u_char        peer[NGX_CTRL_PEER_LEN];
+    size_t        peer_len;
 } ngx_control_request_t;
 
 
@@ -51,6 +57,9 @@
 static ngx_int_t ngx_control_inherit(void);
 static void ngx_control_close(ngx_control_request_t *r);
 static void ngx_control_handle_accept(void);
+static ngx_uint_t ngx_control_loopback(struct sockaddr *sa);
+static void ngx_control_set_peer(ngx_control_request_t *r,
+    struct sockaddr *sa, socklen_t socklen);
 static ngx_int_t ngx_control_handle_read(ngx_control_request_t *r);
 static ngx_int_t ngx_control_content(ngx_control_request_t *r);
 static char *ngx_control_status_text(ngx_uint_t code);
@@ -187,6 +196,12 @@
     }
 #endif
 
+    if (!ngx_control_loopback(&u.sockaddr.sockaddr)) {
+        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
+                      "control: listening on non-loopback address \"%V\" "
+                      "without authentication", &u.url);
+    }
+
     if (ngx_control_inherit() == NGX_OK) {
         ngx_control_inherited = 1;
         return NGX_OK;
@@ -457,17 +472,90 @@
 }
 
 
+static ngx_uint_t
+ngx_control_loopback(struct sockaddr *sa)
+{
+    switch (sa->sa_family) {
+
+    case AF_INET:
+        return (ntohl(((struct sockaddr_in *) sa)->sin_addr.s_addr) >> 24)
+               == 0x7f;
+
+#if (NGX_HAVE_INET6)
+    case AF_INET6:
+        return IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *) sa)->sin6_addr);
+#endif
+
+#if (NGX_HAVE_UNIX_DOMAIN)
+    case AF_UNIX:
+        return 1;
+#endif
+
+    default:
+        return 0;
+    }
+}
+
+
+static void
+ngx_control_set_peer(ngx_control_request_t *r, struct sockaddr *sa,
+    socklen_t socklen)
+{
+    u_char  *p, *last;
+
+    p = r->peer;
+    last = p + NGX_CTRL_PEER_LEN;
+
+#if (NGX_HAVE_UNIX_DOMAIN)
+    if (sa->sa_family == AF_UNIX) {
+
+#ifdef SO_PEERCRED
+        struct ucred  cred;
+        socklen_t     len;
+
+        len = sizeof(struct ucred);
+
+        if (getsockopt(r->fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) {
+            p = ngx_slprintf(p, last, "unix uid:%ui gid:%ui pid:%P",
+                             (ngx_uint_t) cred.uid, (ngx_uint_t) cred.gid,
+                             (ngx_pid_t) cred.pid);
+            r->peer_len = p - r->peer;
+            return;
+        }
+
+        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_socket_errno,
+                      "control: getsockopt(SO_PEERCRED) failed");
+#endif
+
+        p = ngx_cpymem(p, "unix", sizeof("unix") - 1);
+        r->peer_len = p - r->peer;
+        return;
+    }
+#endif
+
+    r->peer_len = ngx_sock_ntop(sa, socklen, p, NGX_CTRL_PEER_LEN, 1);
+
+    if (r->peer_len == 0) {
+        p = ngx_cpymem(p, "-", 1);
+        r->peer_len = p - r->peer;
+    }
+}
+
+
 static void
 ngx_control_handle_accept(void)
 {
     int                     value;
     ngx_fd_t                fd;
     ngx_err_t               err;
+    socklen_t               socklen;
     struct pollfd          *pfd;
+    ngx_sockaddr_t          sa;
     ngx_control_request_t  *r;
 
     for ( ;; ) {
-        fd = accept(ngx_control_pollfd[0].fd, NULL, NULL);
+        socklen = sizeof(ngx_sockaddr_t);
+        fd = accept(ngx_control_pollfd[0].fd, &sa.sockaddr, &socklen);
 
         if (fd == -1) {
             err = ngx_socket_errno;
@@ -499,6 +587,8 @@
         ngx_memzero(r, sizeof(ngx_control_request_t));
         r->fd = fd;
 
+        ngx_control_set_peer(r, &sa.sockaddr, socklen);
+
         ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0,
                        "control accept fd:%d", r->fd);
 
@@ -731,9 +821,12 @@
     ngx_buf_t *body)
 {
     char         *status;
+    ngx_str_t     path;
     ngx_uint_t    n;
     ngx_chain_t  *c;
 
+    static const char  *methods[] = { "-", "GET", "PATCH" };
+
     const char  response_fmt[] =
         "HTTP/1.1 %03ui %s\r\n"
         "Server: " NGINX_VER "\r\n"
@@ -742,6 +835,18 @@
         "Content-Length: %ui\r\n"
         "\r\n";
 
+    if (r->path.len) {
+        path = r->path;
+
+    } else {
+        ngx_str_set(&path, "-");
+    }
+
+    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
+                  "control: client %*s, \"%s %V\" %ui",
+                  r->peer_len, r->peer,
+                  r->method < 3 ? methods[r->method] : "-", &path, code);
+
     c = ngx_alloc_chain_link(r->pool);
     if (c == NULL) {
         return NGX_ERROR;
--- a/docs/man/nginx.8
+++ b/docs/man/nginx.8
@@ -192,6 +192,23 @@
 .Bd -literal -offset indent
 nginx -c ~/mynginx.conf -l unix:/path/to/socket
 .Ed
+.Pp
+The control socket is not authenticated:
+every process that is able to connect to it can read the complete
+configuration, including all included files, and request a reload.
+Use a UNIX-domain socket, which is created with mode 0600 and is
+owned by the user that started
+.Nm
+(usually root), or a loopback address on a host where every local
+account is trusted.
+A non-loopback address exposes the control socket to the network
+and must be protected by host firewalling;
+.Nm
+logs a warning when it is used.
+Every control request is logged to the error log at the
+.Dq notice
+level together with the client address or, for UNIX-domain sockets,
+the credentials of the connecting process.
 .Sh ENVIRONMENT
 The
 .Ev NGINX
```

### CFG-F-1.diff
```diff
--- a/src/os/unix/ngx_control.c
+++ b/src/os/unix/ngx_control.c
@@ -95,7 +95,7 @@
 #ifdef NGX_BUILD
 static ngx_str_t  ngx_control_build = ngx_string(NGX_BUILD);
 #else
-static ngx_str_t  ngx_control_build;
+static ngx_str_t  ngx_control_build = ngx_string("");
 #endif
 
 static ngx_data_decl_t  ngx_control_process_fields[] = {
```

### Regression test
```perl
#!/usr/bin/perl

# GH-CFG-1 regression test for the Control API hardening:
#  (a) every control request is audit-logged with peer, method, path, status
#      (TCP: client address; unix socket: SO_PEERCRED uid/gid/pid);
#  (b) a non-loopback TCP listen address produces a warning.
# Expected to FAIL on an unpatched build (no audit line, no warning).

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::UNIX; };
plan(skip_all => 'IO::Socket::UNIX not installed') if $@;

my $t = Test::Nginx->new()->has(qw/http rewrite control_api/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:8080;
        server_name  localhost;

        location / {
            return 200 "foo";
        }
    }
}

EOF

my $d = $t->testdir();
my $p = port(19100);

$t->args('-l', '127.0.0.1:' . $p)->run()->plan(14);

###############################################################################

# (a) TCP: audit line with client address, method, path and status

like(ctrl("GET /1/nginx HTTP/1.0"), qr/ 200 OK/, 'tcp get');
like(ctrl("PATCH /1/control/config HTTP/1.0"), qr/ 200 OK/, 'tcp reload');
like(ctrl("GET /1/nope HTTP/1.0"), qr/ 404 /, 'tcp not found');
like(ctrl("FOO / HTTP/1.0"), qr/ 405 /, 'tcp unknown method');
like(ctrl("GET /%41 HTTP/1.0"), qr/ 400 /, 'tcp bad request');

$t->stop();

my $log = $t->read_file('error.log');

like($log, qr/\[notice\] \d+#\d+: control: client 127\.0\.0\.1:\d+, "GET \/1\/nginx" 200$/m,
	'audit get');
like($log,
	qr/control: client 127\.0\.0\.1:\d+, "PATCH \/1\/control\/config" 200$/m,
	'audit reload');
like($log, qr/control: client 127\.0\.0\.1:\d+, "GET \/1\/nope" 404$/m,
	'audit not found');
like($log, qr/control: client 127\.0\.0\.1:\d+, "- \/" 405$/m,
	'audit unknown method');
like($log, qr/control: client 127\.0\.0\.1:\d+, "GET -" 400$/m,
	'audit bad request');

# (a) unix socket: SO_PEERCRED uid/pid of the connecting process (us)

$t->write_file('error.log', '');

my $path = "$d/ctrl.sock";
$t->args('-l', 'unix:' . $path)->run();

my $s = IO::Socket::UNIX->new(Peer => $path);
like(http("GET /1/control/processes HTTP/1.0" . "\x0d\x0a\x0d\x0a", socket => $s),
	qr/ 200 OK/, 'unix get');

$t->stop();

like($t->read_file('error.log'),
	qr/control: client unix uid:$< gid:\d+ pid:$$, "GET \/1\/control\/processes" 200$/m,
	'audit unix peer credentials');

# (b) non-loopback TCP address: warning is logged before bind()
# 192.0.2.1 (RFC 5737 TEST-NET-1) is not configured on any interface,
# so bind() fails and nothing reachable is ever opened.

$t->write_file('error.log', '');

system("timeout 10 $Test::Nginx::NGINX -p $d/ -c nginx.conf -e error.log "
	. "-l 192.0.2.1:$p >/dev/null 2>&1");

$log = $t->read_file('error.log');

like($log, qr/\[warn\] \d+#\d+: control: listening on non-loopback address "192\.0\.2\.1:$p" without authentication/,
	'non-loopback warning');

like($log, qr/control: bind\(\) failed/, 'non-loopback bind not possible here');

###############################################################################

sub ctrl {
	my ($line) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => "127.0.0.1:$p"
	) or return;

	return http($line . "\x0d\x0a\x0d\x0a", socket => $s);
}

###############################################################################
```
