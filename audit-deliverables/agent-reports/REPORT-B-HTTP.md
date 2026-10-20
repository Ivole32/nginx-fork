# Agent B — HTTP and Protocol Security — report (ID prefix HTTP-)

Repository: /home/user/nginx-fork @ b38c9d8 (1.31.8 dev). No ASan build was present
at the brief's path, so this is a static review only; nothing was executed or built.
All line numbers refer to the files as they are in this revision.

Summary answer to the brief's questions:

* Client → upstream desynchronization: I found no path by which a client can make
  nginx's own framing disagree with what it forwards. The HTTP/1 front end is strict
  (duplicate Content-Length → 400, TE+CL → 400, non-"chunked" TE → 501, obs-fold → 400,
  bare CR in value → 400, NUL → 400, chunk parser requires CRLF, chunk sizes
  overflow-checked), and every upstream module replaces Content-Length /
  Transfer-Encoding with nginx-generated values (`$proxy_internal_body_length`,
  `$proxy_internal_chunked`, DATA frames for proxy_v2/grpc).
* h1/h2/h3 header validation is consistent: h2 (`ngx_http_v2_validate_header`,
  src/http/v2/ngx_http_v2.c:3284) and h3 (`ngx_http_v3_validate_header`,
  src/http/v3/ngx_http_v3_request.c:705) are byte-for-byte the same rule set; h2/h3 both
  reject Connection/Keep-Alive/Transfer-Encoding/Upgrade/Proxy-Connection and non-"trailers"
  TE; h1 strips the same set before forwarding (ngx_http_proxy_headers[],
  src/http/modules/ngx_http_proxy_module.c:761). The only asymmetry is in *values*
  (HTTP-3 below).
* I found no out-of-bounds read in any state machine I traced (details under
  "Areas reviewed").
* Length-field integer handling: chunk size (NGX_MAX_OFF_T_VALUE/16 pre-check and
  -9 post-check), Content-Length (ngx_atoof), HPACK ints (4 octets max), HTTP/3
  varint/prefix ints (shift==56 guard), Priority integers (15-digit cap + ngx_atoi
  overflow → discarded, commit 82f5fd9) are all bounded.
* Normalized URI vs. what is forwarded: location matching uses the normalized
  `r->uri`, but `proxy_pass` without a URI part forwards `r->unparsed_uri` verbatim,
  including `#fragment` and `%2e%2e` sequences that nginx itself collapsed. This is
  long-standing upstream nginx behaviour, not fork-specific; noted under low-priority.

## Candidates

### HTTP-1
- Title: `tunnel_pass` default target is fully client-controlled (`$host:$request_port`), giving an unrestricted CONNECT forward proxy to any host/port reachable from the nginx box (SSRF to loopback / link-local / RFC1918) unless the operator adds access control.
- Affected: src/http/modules/ngx_http_tunnel_module.c
  `ngx_http_tunnel_pass()` :469-470, `ngx_http_tunnel_eval()` :225-268,
  `ngx_http_tunnel_handler()` :182-221; src/http/ngx_http_parse.c :398-401, :475-493
  (CONNECT authority parsing); src/http/ngx_http_request.c :1188-1206 (authority →
  `r->headers_in.server`, `r->port`).
- Code excerpt (ngx_http_tunnel_module.c:469-474):
  ```c
      if (cf->args->nelts == 1) {
          ngx_str_set(&url, "$host:$request_port");
      } else {
          url = value[1];
      }
  ```
  and ngx_http_tunnel_eval():239-241 `url.no_resolve = 1; if (ngx_parse_url(r->pool, &url) != NGX_OK)`.
- Suspected defect / root cause: The module provides no destination allow-list, port
  restriction, or default deny; the destination comes straight from the CONNECT
  request line (validated only syntactically by `ngx_http_validate_host`, which now
  also admits `%`, sub-delims and `'`). After `ngx_http_upstream_upgrade()` nginx
  becomes a transparent byte pipe in both directions
  (src/http/ngx_http_upstream.c:3627-3681, :3712+), so any TCP service becomes
  reachable through the tunnel, including 127.0.0.1 and 169.254.169.254.
- Input path: client → `CONNECT host:port HTTP/1.1` → request-line parser sets
  host_start/host_end → `ngx_http_validate_host()` → `r->headers_in.server`, `r->port`
  → `$host`, `$request_port` → `ngx_http_tunnel_eval()` → `ngx_http_upstream_init()`
  → connect → `ngx_http_tunnel_process_header()` (200, `u->upgrade = 1`) → raw copy.
  Client controls host and port entirely.
- Preconditions: `tunnel_pass;` (no argument) or `tunnel_pass $host:$request_port;`
  in a reachable `location /` (CONNECT always has URI "/"); no `allow/deny`,
  `auth_basic`, or variable-based target restriction. HTTP/1.1 only (h2/h3 reject
  CONNECT with 405).
- Impact: C/I — SSRF/pivot into internal networks and cloud metadata endpoints from
  an Internet-facing listener; abuse as an open proxy. Realistic when a user copies the
  zero-argument form from docs.
- Confidence: High that the behaviour exists (it is the documented default); Low that
  it is a *bug* rather than a design decision. Reported because the default is
  insecure-by-default and the brief asks about untrusted-input-to-connection paths.
- Tested: nothing (no build). Static trace only.
- Validator should check: whether the module docs require `allow/deny`; whether a
  loopback/link-local/private-range default deny would be acceptable upstream;
  behaviour with `resolver` set (names with `%`, `;`, `'` reach
  `ngx_resolver_create_name_query`, bounded by the 255/63 limits at
  src/core/ngx_resolver.c:3742-3754).

### HTTP-2
- Title: `allow_connect` is server-wide, so enabling `tunnel_pass` anywhere in a server lets CONNECT requests reach every other handler in that server (proxy_pass/fastcgi/static) whose location matches "/", producing `CONNECT / HTTP/1.x` to backends and 2xx responses that clients interpret as an established tunnel.
- Affected: src/http/modules/ngx_http_tunnel_module.c:463-465
  (`cscf->allow_connect = 1;`), src/http/ngx_http_request.c:2098-2111 (only checks
  `allow_connect`, not which location), src/http/ngx_http_parse.c:737-740 (CONNECT
  URI forced to "/"), src/http/modules/ngx_http_proxy_module.c:1184+ (method copied
  verbatim), src/http/modules/ngx_http_chunked_filter_module.c:70-71 and
  src/http/ngx_http_core_module.c:856 (2xx-to-CONNECT special-casing applies regardless
  of handler).
- Excerpt (ngx_http_request.c:2098-2104):
  ```c
      if (r->method == NGX_HTTP_CONNECT) {
          if (r->http_version != NGX_HTTP_VERSION_11 || !cscf->allow_connect) {
              ...NGX_HTTP_NOT_ALLOWED...
  ```
- Suspected defect: the method gate is per-server but the handler that actually
  understands CONNECT is per-location. A `location / { proxy_pass ... }` plus a
  `location = /tunnel { tunnel_pass; }` (or `limit_except` use) is enough. The proxy
  module then sends `CONNECT / HTTP/1.1` with the client's headers to the backend;
  if the backend answers 2xx, nginx relays it without Transfer-Encoding (chunked filter
  skips CONNECT 2xx), with `Connection: close`, and then closes — the client believes a
  tunnel is up. For `tunnel_pass` locations reached via `limit_except`, the handler is
  also installed on the limit_except branch (:432-436).
- Input path: client CONNECT → server with any tunnel_pass → location "/" → non-tunnel
  handler.
- Preconditions: a server mixing tunnel_pass with other handlers at "/".
- Impact: Low. Mostly confusion/robustness (odd requests to backends, confused
  clients); no memory safety or cross-user impact identified.
- Confidence: Medium that the behaviour is as described (static trace); Low that it is
  security-relevant.
- Tested: nothing.
- Validator: confirm whether upstream intends CONNECT to be gated per-location
  (e.g. only when the matched location's handler is the tunnel handler).

### HTTP-3
- Title: HTTP/1 header values that nginx accepts (leading/trailing HTAB, 0x01-0x08, 0x0B, 0x0C, 0x7F) are forwarded unchanged to HTTP/2 upstreams by proxy_v2/grpc, where RFC 9113 §8.2.1 requires the peer to treat them as malformed — asymmetric value validation between what nginx accepts from h1 and what it sends on h2.
- Affected: src/http/ngx_http_parse.c:1017-1060 (`sw_space_before_value` strips only
  SP; `sw_value` rejects only NUL/CR/LF); src/http/modules/ngx_http_proxy_v2_module.c
  :825-852 (`pass_request_headers` loop, `ngx_http_v2_write_value` with no value
  validation); same pattern in ngx_http_grpc_module.c.
- Excerpt (ngx_http_proxy_v2_module.c:844-849):
  ```c
              b->last = ngx_http_v2_write_name(b->last, header[i].key.data,
                                               header[i].key.len, tmp);
              b->last = ngx_http_v2_write_value(b->last, header[i].value.data,
                                                header[i].value.len, tmp);
  ```
- Suspected defect: no normalization (trim HTAB) or rejection of C0/DEL bytes before
  HPACK encoding. The reverse direction is validated (`ngx_http_proxy_v2_validate_header_value`
  :3404) but only for NUL/CR/LF, which mirrors nginx's own leniency and is fine for
  h1 clients.
- Input path: client h1 header `X: \tfoo\t` or `X: a\x0bb` → headers_in → proxy_v2
  create_request → h2 upstream.
- Preconditions: `proxy_http_version 2` (or grpc_pass) and an upstream that enforces
  RFC 9113 (most do: nghttp2, Go, Envoy) → per-request 502/RST_STREAM.
- Impact: A (per-request failure, trivially triggerable but only affects the
  attacker's own request; no smuggling because h2 framing is explicit). Low.
- Confidence: Medium on the mechanism (static), Low on impact.
- Tested: nothing.
- Validator: send `X: \tv` through `proxy_http_version 2` to nghttpd and observe
  PROTOCOL_ERROR; consider trimming OWS and rejecting C0/DEL in the h2 writer.

## Areas reviewed with no issue found

- src/http/ngx_http_priority.c (whole file): all loops bounded by `end`; member/param/
  item/string/token/binary counters; 15-digit integer cap and ngx_atoi overflow →
  OTHER; `-n` safe; empty field = defaults. Sound.
- src/http/v2/ngx_http_v2.c: state_head/state_data/read_data/headers/header_block/
  field_len/field_huff/field_raw/field_skip/process_header/header_complete/
  handle_continuation/priority/priority_update/rst_stream/settings/settings_params/
  window_update/skip_padded/skip/save/headers_save/parse_int/get_node_by_id/
  get_closed_node/create_stream/close_stream/validate_header/pseudo_header/parse_path/
  parse_authority/construct_request_line/priority/process_priority/run_request/
  read_request_body/process_request_body/filter_request_body. Only the PRIORITY_UPDATE
  / RFC 9218 code is new; I traced every node lifecycle (buffered node → HEADERS,
  refused HEADERS, eviction via get_closed_node, close_stream) and found the
  closed-queue / closed_nodes accounting consistent and bounded (≤32 pooled nodes).
  PRIORITY_UPDATE value parsing only touches [pos+4, pos+len) which is verified to
  be in-buffer (:2047-2063). DATA vs Content-Length enforced at :4414-4441.
- src/http/v2/ngx_http_v2_table.c: HPACK static/dynamic lookup, ring-buffer storage
  wrap, table_size ≤ 4096. Upstream-identical.
- src/http/v2/ngx_http_v2.h `ngx_http_v2_stream_precedes` / `queue_frame` /
  filter `waiting_queue`: comparator is a strict total preorder with FIFO tie-break;
  list walks terminate. No corruption path.
- src/http/ngx_http_parse.c: request line (incl. new CONNECT branches: port
  mandatory, HTTP/1.1 mandatory, URI pinned to "/" at :737-740), header line,
  parse_uri, parse_complex_uri (`u -= 4` / `u < uri.data` guard), status line,
  unsafe_uri, multi_header_lines, set_cookie_lines, ngx_http_arg, split_args,
  parse_chunked. Upstream-identical except CONNECT.
- src/http/ngx_http_request.c: process_request_line, process_request_uri,
  process_request_headers, alloc_large_header_buffer (CONNECT uri_start/uri_end are
  inside the request line so the relocation at :1769-1775 covers them),
  process_host, validate_host (stricter than upstream; port now parsed and range-checked),
  process_request_header (CONNECT: HTTP/1.1 + allow_connect + no body),
  read_early_body, headers_in table (Proxy-Authorization unique, Proxy-Connection
  rejected for h2/h3).
- src/http/ngx_http_request_body.c (whole file): length/chunked filters, discard
  path, pipelined-header copy. Upstream-identical.
- src/http/modules/ngx_http_tunnel_module.c (whole file) and the `ignore_input` /
  `upgrade` paths in ngx_http_upstream.c (:2272, :2532, :3306, :3627-3860): no reads
  from upstream before 200; header_in leftovers forwarded; `r != r->main` guarded;
  keepalive forced off for CONNECT.
- src/http/modules/ngx_http_proxy_v2_module.c (whole file): byte-level diff against
  ngx_http_grpc_module.c parse_fragment/validate/rst/goaway/window_update/settings/
  ping shows only log-string and formatting differences. Frame length ≤ 16384,
  static-table-only HPACK (index ≤ 61, size_update must be 0), name/value limits
  against proxy_buffer_size, padding ≤ rest checks, DATA ≤ content-length and
  premature-close checks, flow-control window overflow checks, settings/ping flood
  caps (1000). Request creation: Connection/TE/Upgrade/Keep-Alive/Expect/Host/
  Transfer-Encoding stripped; Content-Length regenerated.
- src/http/modules/ngx_http_proxy_module.c: create_request, process_status_line,
  process_header, input_filter_init, chunked_filter, non_buffered_chunked_filter,
  process_trailer (trailer buffer bounded by proxy_buffer_size). Keepalive only after
  complete framing.
- src/http/modules/ngx_http_fastcgi_module.c process_header/process_record,
  ngx_http_scgi_module.c process_header: upstream-identical.
- src/http/ngx_http_upstream.c process_content_length / process_transfer_encoding
  (duplicates and CL+TE rejected), process_priority (h2 only, r == r->main).
- src/http/v3/ngx_http_v3_parse.c (whole file), ngx_http_v3_table.c (:150-741),
  ngx_http_v3_request.c (:463-1781): varint/prefix-int guards, literal length ≤
  large_client_header_buffers.size and ≤ NGX_MAX_INT_T_VALUE/8 before *8/5,
  insert-buffer capacity check, static/dynamic lookup bounds, base/index arithmetic
  cannot wrap (delta_base < 2^62), DATA vs Content-Length both directions, CONNECT →
  405, same header rules as h2.
- src/http/ngx_http_huff_decode.c `ngx_http_huff_decode` / `_bits`: 256-state table
  indexed by u_char state and 4-bit nibble; `code.next == *state` loop guard; output
  bounded by caller's len*8/5+1 allocation (5-bit minimum code).
- src/core/ngx_proxy_protocol.c (whole file): v1 (addr/port parsing bounded by
  `last`), v2 (header len vs. available, per-family struct size checks, TLV walk with
  `n < sizeof(tlv)` and `n < len` checks, SSL sub-TLV size check), writer side.

## Low-priority notes

- `proxy_pass` with no URI part forwards `r->unparsed_uri` (incl. `#frag` and
  `%2e%2e`) while location/access decisions use the normalized `r->uri`
  (ngx_http_proxy_module.c:1372-1381, ngx_http_request.c:1316-1319). Long-standing
  upstream behaviour; backends that normalize differently can see a different path.
- `client_body_early_read` (new): reads/buffers the body before rewrite/access phases
  using the server-level `clcf` limits (ngx_http_request.c:2217-2258); a request later
  denied by access rules still costs body buffering. Operator opt-in.
- `ngx_http_validate_host` accepts an empty port after ':' (`Host: a:` → port 0) and,
  for `$request_port`, prints nothing for 0; harmless.
- A 2xx to CONNECT carries `Connection: close` (header filter) — RFC-permitted, odd.
- HTTP/2 PRIORITY_UPDATE for not-yet-opened streams: nodes come from the connection
  pool until 32 are closed/parked, then reused; bounded, but a client can keep ~32
  parked placeholders alive per connection. Not an issue.
- HTTP/2 HEADERS frames are not checked against `h2c->frame_size` (upstream-identical);
  header_limit bounds the decoded size.
- proxy_v2/grpc accept a HEADERS frame with stream id 0 as the response headers
  (`ctx->stream_id && ...` guards). Trusted upstream only; upstream-identical in grpc.

## Limitations

- No dynamic testing: the ASan build directory contained no binary and the brief
  restricts to static analysis in that case; nothing was built or run.
- Not read line-by-line: ngx_http_uwsgi_module.c (same template as scgi),
  ngx_http_v3_uni.c/_filter_module.c/_encode.c, ngx_http_v2_filter_module.c beyond
  the queue functions, ngx_http_upstream.c beyond the cited functions, the
  ngx_http_request.c PROXY-protocol read handler (:470-500, :700-760; upstream code),
  ngx_resolver.c name encoding (only the length guards were checked).
- I could not diff against upstream nginx offline; "upstream-identical" judgements are
  from memory of 1.27/1.29 sources plus the in-tree grpc ↔ proxy_v2 diff.
