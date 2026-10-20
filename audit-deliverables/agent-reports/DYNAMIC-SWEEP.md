# Dynamic sanitizer sweep (coordinator)
Build: ASan+UBSan, -O1 -g, gcc 13.3, OpenSSL/PCRE2/zlib system libs, HTTP/2+HTTP/3+stream+mail+dav etc.
Suite: nginx/nginx-tests (shallow clone, 2026-10-20), 511 files, 5368 tests, prove -j6, user root.
Result: no ASan/UBSan log files produced (log_path set, none created). 
Failures: http_listen.t, proxy_bind_transparent.t (exit 2 = skip-like, IPv6 socket() EAFNOSUPPORT),
stream_upstream_resolve.t, stream_upstream_service.t, upstream_service.t (AAAA / fe80::1 upstream -> "socket() failed (97)").
All failures are environmental (container lacks IPv6). SSL tests skipped (no IO::Socket::SSL).
