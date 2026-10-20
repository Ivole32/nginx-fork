# Agent D (Configuration and Access Control) - CFG report

Revision audited: b38c9d8068ab55504aa4311f729803b503579520 (1.31.8 dev). Static review plus live tests against a
private ASan+UBSan build with `--with-control-api` (built into the scratch dir, repo untouched;
binary: /tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/cfg/build-ctrl/nginx,
test tree: .../scratchpad/audit/cfg/t and .../scratchpad/audit/cfg/u, loopback ports 18500-18512 only).

## Candidates

### CFG-1  Control API (`-l addr`) has no authentication or authorization: any party that can connect can dump the full configuration and force a config reload, as root

- Affected files/functions:
  - src/os/unix/ngx_control.c: `ngx_control_init()` 147-268, `ngx_control_handle_accept()` 460-556,
    `ngx_control_content()` 616-704, `ngx_control_print_config()` 913-944, `ngx_control_reload_config()` 982-1023
  - src/core/nginx.c:962-973 (`-l` option), src/core/nginx.c:370-379 (init in main, after `ngx_daemon()`),
    src/core/ngx_conf_file.c:222-233 (config dump forced on when control API enabled)
  - src/os/unix/ngx_process_cycle.c:177-197 (requests are serviced inside `ngx_master_process_cycle()`)
- Code excerpt (ngx_control.c):
  ```c
  /* 470 */  fd = accept(ngx_control_pollfd[0].fd, NULL, NULL);        /* no peer check of any kind */
  ...
  /* 676 */  case 17:
             if (ngx_strncmp(p, "/1/control/config", len) == 0) {
                 if (r->method == NGX_CTRL_PATCH) {
                     return ngx_control_reload_config(r);             /* ngx_init_cycle() in the master */
                 }
                 if (r->method == NGX_CTRL_GET) {
                     return ngx_control_print_config(r);              /* every parsed config file, verbatim */
  ```
  and for TCP listeners nothing restricts the bind address (ngx_control_init 158-243: any `ngx_parse_url()` listen address is accepted).
- Suspected defect / root cause: the control socket is a plain HTTP/1.x endpoint with no credential, token, peer-UID
  (SO_PEERCRED) or source-address check. The only protection is the socket's reachability: for `unix:` sockets the
  file is chmod 0600 (line 247) before `listen()` (line 256), which is correct; for TCP there is nothing. `-l` also
  silently turns on in-memory config dumping for the whole process (ngx_conf_file.c:224), so the master keeps a
  verbatim copy of every config file (including `include`d files) and serves it on GET /1/control/config.
  PATCH /1/control/config calls `ngx_init_cycle()` directly in the master (root) and then respawns workers
  (ngx_process_cycle.c:181-195), i.e. it is equivalent to `kill -HUP master`.
- Input path: any process able to `connect()` to the control address. For `-l 127.0.0.1:PORT` that is every local
  user; for `-l 0.0.0.0:PORT` / an external address it is any remote host. Request parsing
  (`ngx_control_parse_request_line`, 1056-1474) runs in the master process with root privileges; the request body
  is never read, headers are ignored, max request line 1024 bytes.
- Preconditions: nginx built with `--with-control-api` and started with `-l <tcp addr>` (not single-process mode).
  Not enabled by default; the option is new in 1.31.5 (docs/xml/nginx/changes.xml:312-320) and the man page/help
  text (nginx.c:433) does not warn that the endpoint is unauthenticated.
- Impact: C - full configuration disclosure to unprivileged local users (or remote parties if bound non-loopback):
  upstream credentials in `proxy_pass http://user:pass@`, secure_link secrets, auth file paths, internal
  topology, etc. A/I - unauthenticated forced reload: workers are respawned and in-flight connections are
  gracefully drained on every PATCH; a config that an admin left temporarily broken is reloaded at an attacker-chosen
  time; reload log lines (file names, directive errors) are returned to the caller. No code execution: the request
  parser is tight (see tests) and the only actions are GET-style status and reload.
- Confidence: High. Verified by code reading and by a live test.
- What I tested (ASan build, `-l 127.0.0.1:18500`, master running as root, `user nobody nogroup`):
  - As uid 65534 (`setpriv --reuid=65534 ...`): `GET /1/control/processes` -> 200 with worker pid;
    `GET /1/control/config` -> 200 with the full nginx.conf and the included inc.conf contents (a marker comment
    in the include was returned verbatim); `PATCH /1/control/config` -> `200 {"logs":[]}`, after which
    `/1/control/processes` showed a new worker pid (12235 -> 12363) and HTTP on :18501 kept working.
  - Parser probes (2000-byte line, 1024/1025-byte lines, control bytes, `%`, `..`, `//`, bare LF, HTTP/1.2, host
    forms `http://h?x`, `http://[::1]zzzz/1/nginx`, high bytes, a PATCH with a body, 70 simultaneous idle
    connections): all answered 200/400/404 or were closed; "too many client connections" closes the oldest
    connection (ngx_control.c:489-496); no ASan/UBSan reports in the master; service continued afterwards.
  - `-l unix:...`: socket created `srw------- root root`; root can connect, uid 65534 gets EACCES; socket file is
    removed on QUIT.
- Open questions for a validator: whether the project considers "bind it to a unix socket" the intended deployment
  (the tests in nginx-tests use `127.0.0.1:port`, which makes the API reachable by every local account). If TCP is
  meant to be supported, the fix would be peer checks (SO_PEERCRED for unix, at minimum loopback-only + a token for
  TCP) and/or documentation. Also confirm there is no intended `allow/deny` integration I missed (grep for "control"
  in src/http and src/core finds none).

## Areas reviewed with no issue found

- src/os/unix/ngx_control.c request parser (`ngx_control_parse_request_line`): bounded by the 1024-byte
  `ngx_create_temp_buf` (547); `b->last == b->end` guard (570); `usual[]` bitmap indexed `ch >> 5` fits 8 entries;
  path length only set at ' '/'?'; `ngx_control_content` compares with `ngx_strncmp(..., len)` on exact lengths;
  trailing slash stripped only when len > 1. Fuzzed as above with no fault.
- ngx_control.c socket setup: `bind()` -> `chmod(0600)` -> `listen()` ordering (238-256) means the window where the
  unix socket is 0777 (umask(0) from ngx_daemon.c:37) cannot be exploited, because `connect()` fails before
  `listen()`; accepted fds get FD_CLOEXEC; workers close all control fds in `ngx_worker_process_init`
  (ngx_process_cycle.c:794), so a compromised worker cannot read control connections.
- `ngx_control_unix_path[NGX_UNIX_ADDRSTRLEN]` (78) is always NUL-terminated: ngx_inet.c
  `ngx_parse_unix_domain_url` rejects `len+1 > sizeof(sun_path)`, so host.len <= 107 < 108.
- Binary-upgrade handoff (`ngx_control_handoff` 298-310, `ngx_control_inherit` 401-431, `NGINX_CTRL` env read in
  `ngx_control_preinit` before `ngx_init_cycle` can replace environ): env is only trusted if `-l` is also given; only
  the process that execs nginx controls it; `ngx_control_uninit` 271-284 only unlinks the socket path when it owns it.
- src/core/ngx_cycle.c: pid file (`ngx_create_pidfile` 1032-1071, O_TRUNC 0644 in a root dir), lock file
  (`ngx_test_lockfile`, only without atomic ops), shm zone reuse (420-500: name+tag+size must match to reuse; a
  tag mismatch or size change allocates a fresh zone; `noreuse` zones get old `data` only for the same tag, used by
  upstream_zone to copy peers; `ngx_shared_memory_add` 1337-1349 rejects name reuse by another module/size),
  `ngx_create_paths` (ngx_file.c:598-656: mkdir 0700, chown to worker user, u+rwx only).
- src/core/ngx_conf_file.c `ngx_conf_include` (827-890): glob only on `*?[`, paths resolved against prefix; dump
  buffers sized from the file's stat size (`ngx_conf_add_dump` 105-156) and only enabled with -T/-l/debug.
- src/core/nginx.c `ngx_load_module` (1630-1700): refuses after modules are used, path from config prefix only;
  dlopen of admin-controlled file (by design).
- src/os/unix/ngx_process_cycle.c `ngx_worker_process_init` (780-960): setgid -> initgroups -> (KEEPCAPS only
  with `transparent`) -> setuid -> capset(CAP_NET_RAW) -> PR_SET_DUMPABLE -> chdir; `initgroups` failure is
  non-fatal (upstream behaviour). Master keeps root only for the master loop; control-API work runs there (CFG-1).
- src/os/unix/ngx_process.c signal handler (319-440) and `ngx_spawn_process` (socketpair, nonblocking, FIOASYNC,
  F_SETOWN, FD_CLOEXEC on both ends); ngx_channel.c `ngx_read_channel` (100-200): validates SCM_RIGHTS
  level/type and length before taking an fd; ngx_setproctitle.c; ngx_user.c (`crypt_r` with per-call
  `crypt_data`); ngx_daemon.c.
- src/http/ngx_http_core_module.c: `ngx_http_map_uri_to_path` 1979-2050 - the "Avoid post-rewrite URI to path
  mapping with alias" fix (f8a2342) is present (`alias && (!r->valid_location || r->uri_changed)` -> NULL) and
  the "URI shorter than aliased URI part" check follows; flags are maintained in ngx_http_script.c 1180-1189 /
  1595-1601, reset in find_config (989), internal redirect (2722) and named locations; the classic
  `location /foo { alias /bar/; }` + `/foo../` pattern is unchanged upstream behaviour (not a code defect, config
  footgun). `ngx_http_core_find_config_phase` 980-1072 enforces `internal` (404 unless r->internal);
  `ngx_http_core_find_location`/`find_static_location` 1446-1600 incl. the new predicate locations (`location
  $var`) treat an error as NGX_ERROR (the changes.xml bugfix is in place); access/post_access phases
  1119-1230 implement `satisfy any/all` exactly as upstream (401/403 precedence, auth_delay);
  `ngx_http_core_root` 4654-4760 rejects `$document_root`/`$realpath_root` in root/alias and marks regex/predicate
  aliases as NGX_MAX_SIZE_T_VALUE; `ngx_http_set_disable_symlinks` and ngx_open_file_cache.c
  `ngx_open_file_wrapper` 614-780 (openat + O_NOFOLLOW per component, owner check variant) are intact.
- src/http/modules: access (CIDR masks, v4-mapped v6, unix: rule "TODO path" is upstream), auth_basic (htpasswd
  scanning bounded by NGX_HTTP_AUTH_BUF_SIZE with carry-over; buffer zeroed; `user.data[login]` read at
  `login == user.len` hits the ':' separator as upstream), auth_request (only 2xx -> OK, 401/403 propagated,
  WWW-Authenticate copied), realip (`ngx_http_get_forwarded_addr[_internal]` 2098-2200: XFF walked from the
  right, each hop must match `set_real_ip_from`, non-recursive takes only the last hop; PROXY protocol port
  applied only for `proxy_protocol`), referer (256-byte host buffer bounded), secure_link (constant-time compare
  for both modes, base64url length <= 24 and decoded == 16, expiry vs ngx_time()), limit_req / limit_conn
  (empty key skips the limit - documented behaviour; key length caps 65535 / 255), try_files (alias handling
  matches map_uri_to_path incl. the NGX_MAX_SIZE_T_VALUE / add_uri_to_alias branch), index, static (dir
  redirect escapes URI, uses Location without host unless absolute_redirect), geo (proxies via the same forwarded
  logic), map (hostnames trailing-dot), upstream_sticky (client cookie/route only acts as a `pc->hint`;
  `ngx_http_upstream_get_rr_peer_by_sid` still honours `tried`, `down`, max_fails; sids are <= 32 bytes because
  `route=` is length-checked in ngx_http_upstream.c:6665 and auto sids are 32 hex chars, so the `sid[32]`
  copies in sess_create/learn_peer cannot overflow; cookie attributes come from config/complex values),
  upstream_zone (sid buffer NGX_HTTP_UPSTREAM_SID_LEN, resolver timers per worker).
- src/stream/ngx_stream_access_module.c (same logic as http), ngx_stream_ssl_preread_module.c record parser
  (SNI/ALPN length checks `ext < 3 + size`; memory aspects left to the memory agent).
- src/mail/ngx_mail_auth_http_module.c `ngx_mail_auth_http_create_request`: login/password/raw cert escaped with
  NGX_ESCAPE_MAIL_AUTH (same table as memcached: all < 0x20, 0x7f, >= 0x80 incl. CR/LF are %-escaped); salt already
  carries CRLF; SMTP HELO/FROM/TO come from the line parser and cannot contain CR/LF; `ahcf->header` is config.
- Logging: ngx_http_log_module.c `ngx_http_log_escape` 1076-1133 escapes 0x00-0x1f, '"', '\\', 0x7f and >= 0x80
  as \xHH; `ngx_escape_json` handles '"', '\\' and controls; `escape=none` is explicit opt-in. ngx_syslog.c
  `ngx_syslog_writer`/`add_header` 237-285: tag validated at config time (alnum/_ <= 32), message truncated to
  NGX_SYSLOG_MAX_STR; no injection point from request data beyond what the (escaped) log format supplies.
- ngx_log.c: error logs opened 0644 append with FD_CLOEXEC (ngx_cycle.c 380-408); ngx_file.c
  `ngx_create_temp_file` uses O_CREAT|O_EXCL 0600 (ngx_files.c `ngx_open_tempfile`) and unlinks non-persistent
  files immediately; hashed temp dirs created 0700 (`ngx_create_path`).

## Low-priority notes

- Control API event loop lost-wakeup (ngx_control.c 327-398 + ngx_process_cycle.c 178): `poll(.., 0)` is run once
  per SIGIO and every fd is serviced once; bytes already queued when the read returned NGX_AGAIN are not consumed
  until *another* SIGIO arrives on any control fd. Observed: a 2000-byte request line produced no reply (client
  timeout) and was only closed with "request too large" when the next connection arrived. Liveness only.
- Control reload uses a stack-allocated `ngx_log_t` (ngx_control.c:986, 997-1005) as `old_cycle->log` for
  `ngx_init_cycle()`. Modules that copy `cf->log` into long-lived structs (e.g. `conf->ssl.log = cf->log`,
  ngx_http_ssl_module.c:745, stream/mail/proxy/grpc/uwsgi equivalents, geo/map temp pools) therefore keep a
  dangling stack pointer in the new cycle. I verified every `ssl->log` use is config-time only, and the SIGHUP path
  has the same lifetime property (old cycle pool is destroyed immediately in the master, ngx_cycle.c:782-787), so
  no runtime use was found; still fragile (a future runtime use of `ssl->log` would be a stack UAF in the master).
  ASan with detect_stack_use_after_return=1 reported nothing during the reload test.
- Control-API reload does not check `ngx_new_binary` (ngx_process_cycle.c:181 vs the SIGHUP branch at 236-243):
  a PATCH during a binary upgrade re-reads the config and respawns workers in the old master. Operational only.
- `-l` forces config dumping for every mode (ngx_conf_file.c:224), so the master permanently holds all config
  text in memory (visible in core dumps / via CFG-1).
- Control API responses carry `Server: nginx/<version>` and `/1/nginx` returns version+build string; the reload
  response returns error-log lines (file paths). Minor information exposure, only to whoever can already connect.
- auth_basic: `ngx_strcmp(encrypted, passwd->data)` is not constant-time and the "user not found" vs "password
  mismatch" difference is only logged, not returned (upstream behaviour); `crypt()` cost dominates timing.
- `initgroups()` failure during privilege drop is logged but not fatal (upstream behaviour, ngx_process_cycle.c:840).
- Default-build nginx (without `--with-control-api`) has none of the control-API code paths; CFG-1 is strictly
  opt-in.

## Limitations

- Did not review ngx_http_split_clients_module.c, ngx_http_map_module.c beyond the handler entry, the stream
  realip/geo modules, ngx_http_variables.c handlers other than document_root/realpath_root/request_filename, or
  ngx_mail_auth_http's response parser for logic flaws (only the request-building side for injection).
- Memory-safety of ssl_preread/sticky slab code was only skimmed (other agents' scope).
- Could not test as a genuinely remote client; local unprivileged-user tests stand in for "anyone who can connect".
- Did not test binary upgrade (USR2) with the control socket handed over via NGINX_CTRL.
