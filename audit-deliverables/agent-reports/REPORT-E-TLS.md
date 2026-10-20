# Agent E (TLS and Cryptographic Security) - NGINX source audit

Revision audited: b38c9d8 (1.31.8 dev). Static review + one live test against the
provided ASan build (OpenSSL 3.0.13), loopback only.

## Candidates

### TLS-1 - Per-vhost client-certificate policy bypassed when the client omits SNI
- Affected: src/http/ngx_http_request.c
  - ngx_http_set_virtual_server() lines ~2488-2540 (the SNI/Host mismatch guard)
  - ngx_http_process_request() lines ~2148-2192 (client cert verification)
- Code excerpt (the guard that does NOT fire without SNI):
```
    hc = r->http_connection;
#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
    if (hc->ssl_servername) {                 /* only when SNI was sent */
        if (hc->ssl_servername->len == host->len
            && ngx_strncmp(...) == 0) { ... return NGX_OK; }
    }
#endif
    rc = ngx_http_find_virtual_server(r->connection,
                                      hc->addr_conf->virtual_names, host, r, &cscf);
    ...
#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
    if (hc->ssl_servername) {                 /* mismatch -> 421, only with SNI */
        ...
        if (sscf->verify) {
            ... ngx_http_finalize_request(r, NGX_HTTP_MISDIRECTED_REQUEST);
```
  And the verification in ngx_http_process_request uses the TLS handshake's result,
  which was computed against the *negotiated* (default) server's CA set:
```
    sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module); /* target vhost */
    if (sscf->verify) {
        rc = SSL_get_verify_result(c->ssl->connection);  /* done vs default server */
        ...
        if (sscf->verify == 1) {
            cert = SSL_get_peer_certificate(c->ssl->connection);
            if (cert == NULL) { ... no required cert ... }
```
- Suspected defect / root cause: The TLS handshake (and thus client-certificate
  request, trust anchor, and SSL_get_verify_result) is bound to the server selected
  by SNI, or to the listen default_server when no SNI is sent. The HTTP request is
  then (re-)routed by the Host header in ngx_http_set_virtual_server(). The guard
  that rejects a Host which disagrees with the negotiated server, and that enforces
  "different server name than negotiated" -> 421 when the target requires client
  verification, is entirely enclosed in `if (hc->ssl_servername)`. hc->ssl_servername
  is only set when the client sent an SNI that matched a virtual server
  (ngx_http_ssl_servername). If the client sends NO SNI, the connection terminates on
  the listen default_server, its SSL_CTX (its CA list / verify mode) governs the
  handshake, and the Host header can still route the request to a different vhost on
  the same listen socket whose stricter `ssl_verify_client`/`ssl_client_certificate`
  (different CA) is never applied. process_request's `sscf->verify` re-check only
  re-reads the same handshake verify result and peer cert, both produced under the
  default server's policy, so it passes.
- Input / execution path (attacker = remote TLS client):
  1. Attacker opens a TLS connection with NO SNI -> lands on listen default_server A.
  2. Server A requests+verifies client certs under CA_A (e.g. ssl_verify_client
     optional/on with ssl_client_certificate caA.crt). Attacker presents a valid
     CA_A client cert; handshake verify result = X509_V_OK.
  3. Attacker sends `Host: b.example`, where server B on the same address has
     `ssl_verify_client on; ssl_client_certificate caB.crt;` (a different trust
     anchor). Request is routed to B by Host.
  4. B's verification re-check reads the A-handshake result (OK) and the (CA_A) peer
     cert (non-NULL) and admits the request. B's CA_B requirement is bypassed.
- Preconditions: HTTP/1.x or HTTP/2 over TLS; at least two server{} blocks sharing a
  listen address; the default/negotiated server requests client certs under a trust
  anchor the attacker can satisfy, while the Host-targeted server enforces a stricter
  or different client-cert policy. No attacker-controlled config.
- Impact: Integrity/authentication bypass - client-certificate access control of a
  protected virtual host is defeated by omitting SNI. Confidentiality/Integrity of
  that vhost's resources. Not a crash/DoS.
- Confidence: Medium. The code path and the missing re-check are unambiguous and I
  reproduced the bypass live (see test). Rated Medium rather than High because this
  is partly a known nginx design limitation (the 421 guard was added specifically for
  the SNI-present case) and exploitation requires a specific multi-vhost +
  mixed-CA/verify configuration; reasonable people may classify it as a
  configuration hazard rather than a code defect. It is nonetheless a real,
  demonstrable client-auth bypass and the guard's SNI-only scope is the root cause.
- What I tested and the actual result (ASan build, 127.0.0.1:18443; server A =
  default, verify optional, CA_A; server B = verify on, CA_B):
  - Test 1: NO SNI, client cert = clientA (CA_A), `Host: b.example`
    -> `HTTP/1.1 200 OK  server=B(PROTECTED) verify=SUCCESS dn=CN=clientA` -- BYPASS.
  - Test 2 (control): SNI=a.example, same cert, Host: b.example -> 421 Misdirected.
  - Test 3 (control): SNI=b.example, CA_A cert -> 400 (B rejects wrong-CA cert).
  - Test 4: SNI=c.example (unknown, declined -> default server A), CA_A cert,
    Host: b.example -> `200 OK server=B(PROTECTED) verify=SUCCESS` -- also BYPASS.
  - Test 5 (control): NO SNI, no client cert, Host: b.example -> 400 (no required cert).
  error.log confirmed B's path was reached ("server: b.example", host "b.example")
  in the bypass cases while the control cases logged the expected rejections.
- Open questions / what a validator should check:
  - Whether nginx intends `ssl_verify_client` to be enforceable per-vhost on a shared
    listener without `ssl_reject_handshake` on the default server. Upstream guidance
    is often "give the protected vhost its own IP/listener or reject_handshake"; if
    so this is a hardening/documentation item rather than a code fix.
  - Confirm the same gap in stream (ngx_stream_ssl_module has no Host layer, so less
    relevant) and that HTTP/2 coalescing does not widen it further.
  - A fix would extend the mismatch/verify re-check to the no-SNI case (e.g. when the
    routed vhost differs from the negotiated SSL_CTX and requires verification,
    respond 421).

## Areas reviewed with no issue found
- src/event/ngx_event_openssl.c session cache (ngx_ssl_new_session /
  ngx_ssl_get_cached_session / ngx_ssl_remove_session / ngx_ssl_expire_sessions):
  i2d length now guarded with `len <= 0 || len > NGX_SSL_MAX_SESSION_SIZE` (commit
  faf9438) so the 8192-byte ngx_ssl_session_buffer copy is bounded; session_id_length
  bounded to <=32 before copy into id[32]; slab alloc sizes consistent for 32/64-bit;
  buffer copied under shmtx then d2i after unlock. Sound.
- Session reuse across virtual hosts: ngx_ssl_session_id_context() folds sess_ctx +
  all server certs (X509_digest) + the client CA list (X509_NAME_digest) into the
  SSL_CTX session_id_context. Servers with different certs or different client-CA
  lists get different contexts, so OpenSSL refuses to resume a session from a server
  with a different verification policy. This defeats the "resume across servers to
  dodge verification" hypothesis. Sound. (Note: this is why TLS-1 must use a fresh
  no-SNI handshake, not resumption.)
- Session ticket key rotation (ngx_ssl_rotate_ticket_keys / ticket_key_callback /
  "synced all session ticket keys" commit 1916f26): keys generated via RAND_bytes,
  zeroed with ngx_explicit_memzero, 3-slot rotation under shmtx, AES-128/256-CBC +
  HMAC-SHA256, TLS1.3 tickets forced renew. IV via RAND_bytes each encrypt. No nonce
  reuse. Sound.
- ngx_ssl_ticket_key_callback name lookup uses ngx_memcmp on 16-byte key names - these
  are public key identifiers, not secrets, so non-constant-time is fine.
- ngx_ssl_shutdown / shutdown_without_free / kTLS EIO (commit e72a6a0): on
  shutdown_without_free the SSL object is intentionally kept (lingering close);
  otherwise SSL_free then c->ssl=NULL. c->ktls_recv set from BIO_get_ktls_recv before
  the free, and NGX_EIO is suppressed only in ngx_connection_error under ktls_recv.
  No UAF/double-free found on these paths.
- ngx_ssl_recv / ngx_ssl_handle_recv / ngx_ssl_write / send_chain / sendfile /
  recv_early / write_early: error transitions set read/write error+eof and
  no_wait/no_send_shutdown consistently; renegotiation dropped (CVE-2009-3555 guard).
  No state left inconsistent that I could find.
- QUIC ngx_event_quic_protection.c: AEAD nonce = per-key IV XOR packet number
  (ngx_quic_compute_nonce), packet numbers are unique per space, so no nonce reuse;
  retry packet uses the RFC9001 fixed key/nonce over fixed input (correct); HKDF
  labels match RFC 9001; ngx_quic_parse_pn matches the RFC pseudo-code; reserved-bit
  and zero-length-payload checks enforced. Sound.
- QUIC key update (ngx_quic_keys_update / keys_switch, ngx_event_quic.c key_phase):
  next keys derived with "tls13 quic ku", trial decryption with next_key on key-phase
  mismatch to avoid a timing oracle (RFC 9001 6.3/9.5), secrets zeroed. Sound.
- QUIC tokens (ngx_event_quic_tokens.c): AES-256-GCM, RAND_bytes IV, length sanity
  checks on token, addr_hash compared with ngx_memcmp (not secret-sensitive -
  authenticity comes from GCM tag), expiry enforced, odcid length bounded to
  NGX_QUIC_MAX_CID_LEN and to remaining buffer. Sound.
- QUIC openssl compat (ngx_event_quic_openssl_compat.c): keylog hex parse bounds n to
  EVP_MAX_MD_SIZE; record buffers sized with +SSL3_RT_HEADER_LENGTH+TAG. Sound.
- src/stream/ngx_stream_ssl_preread_module.c: ClientHello state machine - extension
  arithmetic (sw_sni_len/sw_alpn_*) checks `ext < 3 + size` / `ext < 1 + size` before
  subtracting; `left < size` checked each iteration; dst buffers (host, alpn) are
  pnalloc'd to the declared ext length before writing; `n = ngx_min(last-pos, size)`
  caps copies. No OOB found.
- ngx_crypt.c: apr1 (1000-round MD5, matches Apache), {SSHA}/{SHA} via SHA1, {PLAIN}.
  These are password-hash verifiers; final compare is ngx_strcmp in
  ngx_http_auth_basic_crypt_handler - non-constant-time but comparing hashes/derived
  strings, standard for htpasswd. ssha decode length clamped to >=20. No misuse.
- ngx_http_secure_link_module.c: both new and legacy variables use an explicit
  constant-time loop (`ch |= hash[i]^md5[i]`). base64url hash length validated ==16.
  Sound.
- ngx_http_userid_filter_module.c: cookie length checked >=22, base64 decode into
  fixed uid_got[16] from exactly 22 chars. No overflow.
- ngx_ssl_check_host / ngx_ssl_check_name (upstream cert verification): uses
  X509_check_host/X509_check_ip when available; IP SAN vs dNSName separation
  (commit d10dd31) prevents IP-in-dNSName confusion. Upstream proxy_ssl_verify path
  (ngx_http_upstream_ssl_handshake) checks SSL_get_verify_result AND
  ngx_ssl_check_host against u->ssl_name. Sound.
- OCSP stapling/validation (ngx_event_openssl_stapling.c): OCSP_basic_verify +
  OCSP_resp_find_status + OCSP_check_validity(300s skew) enforced; nextUpdate parsed
  via BIO/asctime trick; responder URL requires http:// prefix and non-empty host;
  response capped at 16384 buffer; Content-Type validated. Status-line/header parsers
  are bounded FSMs. No memory-safety or validation bypass found.
- ngx_event_openssl_cache.c: object cache keyed by (hash,type,id) with
  ngx_memn2cmp full-key compare (no cross-type/cross-name collision); reload uses
  mtime+uniq (file) and inheritable flag; ref/free use up_ref/pop_free correctly;
  "data:" certs via BIO_new_mem_buf with correct length. Key cross-server-confusion
  not found - keys include the full path/data string.
- Defaults: ssl_protocols default = TLSv1.2|TLSv1.3 (NGX_SSL_DEFAULT_PROTOCOLS);
  ssl_verify_client default 0 (off); verify_depth default 1; SSL_OP_NO_COMPRESSION,
  SSL_OP_NO_CLIENT_RENEGOTIATION, SSL_OP_NO_ANTI_REPLAY, SSL_OP_IGNORE_UNEXPECTED_EOF
  set; min/max proto bounded. proxy_ssl_verify default off (documented). No insecure
  default beyond the documented proxy_ssl_verify=off.

## Low-priority notes
- proxy_ssl_verify defaults to off (src/http/modules/ngx_http_proxy_module.c:3978).
  Documented default; upstream server identity unverified unless enabled. Config
  hygiene item, not a code defect.
- ssl_stapling_verify defaults to off (OCSP responses accepted with OCSP_NOVERIFY).
  Matches upstream and documentation; stapled data is also client-visible, low risk.
- ngx_ssl_verify_callback always returns 1 and only logs under NGX_DEBUG; actual
  enforcement is via SSL_VERIFY_PEER + post-handshake SSL_get_verify_result checks.
  This is the intended nginx design (so that optional/optional_no_ca can inspect the
  result later); not a bug, but it means a misread of this function could suggest
  verification is disabled - it is not.
- ngx_ssl_password_file / ocsp 2048-byte pool / response 16384 cap: all bounded;
  password buffers zeroed with ngx_explicit_memzero. Noted as fine.

## Limitations
- Only one live test performed (the TLS-1 bypass). All QUIC, OCSP-network,
  session-ticket-rotation and kTLS findings are from static reading; I did not stand
  up a QUIC client, an OCSP responder, or kernel-TLS to exercise those paths at
  runtime.
- I did not audit ECH (ngx_ssl_ech_files) or certificate-compression paths in depth,
  nor the BoringSSL/QuicTLS/OpenSSL-3.5 QUIC API variants beyond reading - the ASan
  build links OpenSSL 3.0.13 (compat/QUIC-OpenSSL-compat path), so other API branches
  were read but not executed.
- I did not attempt to exercise reload-time cert cache staleness or shared-memory
  session-cache exhaustion under concurrency.
