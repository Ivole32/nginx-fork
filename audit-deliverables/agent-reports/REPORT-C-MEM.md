# Agent C (Memory Safety) - NGINX fork audit report

Revision audited: b38c9d8068ab55504aa4311f729803b503579520 (nginx 1.31.8 dev fork).
Method: line-by-line read of every file listed in scope, compared against my knowledge of upstream nginx (the fork's history is a single squashed import `df5269c` plus 49 commits, so "unchanged upstream code" could not be established via git; every function listed below was actually read). The ASan+UBSan build at scratchpad/build-asan was present but was configured WITHOUT `--with-http_json_module`, so the new JSON parser was exercised with a standalone ASan/UBSan harness that compiles `src/core/ngx_json_parse.c` and `src/core/ngx_json_unescape.c` directly (harness and repro: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/memc/json_harness.c`, `.../memc/skip_repro.c`).

Bottom line: I found NO attacker-reachable out-of-bounds read/write, integer overflow in length math, use-after-free, uninitialized use, or unchecked allocation in the files in scope. One low-severity API-contract defect in the new JSON parser is reported as a candidate because it is a real, reproducible behaviour, but it is not reachable through the only in-tree consumer.

## Candidates

### MEM-1: ngx_json_parse: a scalar `NGX_JSON_SKIP` inside an array suppresses the enclosing `ARRAY_CLOSE` event (consumer stack desync; not reachable via ngx_http_json_module)

- Affected: `src/core/ngx_json_parse.c`, `ngx_json_emit()` lines 753-763, interaction with `ngx_json_close()` lines 791-807 and the skip-stop test at lines 89-99.
- Code excerpt:
  ```c
  /* ngx_json_emit(), lines 753-763 */
  case NGX_JSON_VALUE_STRING: ... case NGX_JSON_VALUE_NULL:
      if (ctx->depth > 0
          && ctx->stack[ctx->depth - 1] == ngx_json_ctx_array
      ) {
          ctx->skip_until_depth = ctx->depth - 1;
      }
      break;
  /* ngx_json_close(), lines 797-799 */
  ctx->depth--;
  rc = ngx_json_emit(ctx, event, p, 1);   /* suppressed: still skipping */
  ```
- Defect / root cause: the comment in `ngx_json_emit()` says a scalar skip "skip[s] the rest of that array". `skip_until_depth` is set to `depth - 1`, so when the array's `]` is processed, `ngx_json_close()` decrements depth and then calls `ngx_json_emit()` while `skip_until_depth` is still set, so the `ARRAY_CLOSE` is swallowed; skipping only stops on the *next* byte (loop-top test). The consumer saw `ARRAY_OPEN` (and, in the HTTP module's design, pushed a frame for it) but never sees the matching close.
- Reproduction (deterministic, `skip_repro.c`, input `{"a":[1,2],"b":3}`, handler returns SKIP on number `1`): events delivered were `OBJ_OPEN, KEY a, ARR_OPEN, NUM 1 (SKIP), KEY b, NUM 3, OBJ_CLOSE` - no `ARR_CLOSE`. Fuzzing with random scalar skips reproduces "KEY outside object" / "frame left on stack after NGX_OK" invariant failures; with only container/key skips (what the HTTP module does) 3,000,000 parses across 5 seeds passed all invariants with no ASan/UBSan findings.
- Input path: JSON text comes from any variable named in `json_set` (e.g. `$request_body`, `$arg_x`, a header); the HTTP module `ngx_http_json_handler()` (`src/http/modules/ngx_http_json_module.c` lines 672-836) only returns `NGX_JSON_SKIP` on `KEY`/`KEY_ESCAPED` (line 779) and on container `OPEN` (line 712), never on scalar values, so this path is NOT exercised in-tree. If a future consumer uses scalar skips while tracking a frame stack like the HTTP module does, it would pop the wrong frame on later CLOSE events (the module's pop is guarded by `top != NULL`, so no underflow).
- Preconditions: a consumer returning `NGX_JSON_SKIP` on a `VALUE_*` event inside an array. None in-tree.
- Impact: none today (API hazard / logic desync for future users; no memory corruption even in the HTTP module's stack handling because `nelts--` is guarded).
- Confidence: High that the behaviour exists (reproduced); High that it is not reachable via ngx_http_json_module.
- Validator: confirm no out-of-tree/dynamic module uses scalar SKIP; consider fixing by resetting `skip_until_depth` before emitting the close when `ctx->depth <= skip_until_depth` in `ngx_json_close()`.

## Areas reviewed with no issue found

JSON (new code):
- `src/core/ngx_json_parse.c` whole file: state machine validates `\uXXXX` hex, lone surrogates (both orders) are rejected (lines 364-373, 413-420), control chars < 0x20 rejected (326), depth bounded by `max_depth` before push (815-817) with the stack lazily sized to `max_depth` (820-821); `after_value`/`close` only touch `stack[depth-1]` when depth>0; `start` is always assigned before any emit in a single call (the parser is only ever called with the whole value in one call: `ngx_http_json_variable()` line 328, so the "bare top-level number at end of input" path at 654-666 never sees `start == NULL`). ASan/UBSan fuzz (3M parses incl. mutations, nesting up to 70 with max_depth 1..70) clean.
- `src/core/ngx_json_unescape.c`: output never exceeds input (every escape is >= its decoded size), guarded by `dst->len < src->len` (184); surrogate pair arithmetic bounded to <= 0x10FFFF; 4-byte UTF-8 encoder correct; `ngx_json_hex_digit()` correct. Every parser-validated escaped token unescaped successfully in the harness (consistency between validator and decoder).
- `src/http/modules/ngx_http_json_module.c`: `key_buffer` growth (763-783) allocates >= token->len before unescape; `ngx_http_json_store()` allocates `value->len` for unescape; CLOSE slice `token->data - top->start + 1` is within the source buffer; per-request `values` array sized by config; frame stack `nelts--` guarded by `top != NULL`; config-time path parser (`ngx_http_json_insert_path`) only runs on trusted config.
- `src/core/ngx_json.c` (render) and `src/core/ngx_data.c`: length pass uses overflow checks against `NGX_MAX_SIZE_T_VALUE`; `ngx_json_integer_length()` = `NGX_INT64_LEN` (20) covers INT64_MIN; `ngx_data_time_handler()` buffer 24 bytes = exact max output; only used by the Control API for output.

Script engine:
- `src/http/ngx_http_script.c` `ngx_http_script_run()` (622-676): verified the fix - `e.end = value->data + n` excludes the reserved tail, every copy code (`copy`, `copy_var`, `copy_capture`, `regex_end` args) calls `ngx_http_script_check_length()` (827-841), and the final `value->len = e.pos + len - value->data` is therefore <= `n + len`. Same pattern correctly applied in `src/stream/ngx_stream_script.c` (520-560). The reserved byte is consumed safely by `ngx_http_log_module.c:552` (`log.data[log.len-1]='\0'`), `ngx_http_variables.c:1686+` (`$realpath_root`), and `ngx_http_core_module.c:2018-2051` (`ngx_http_map_uri_to_path`, which reserves `uri.len - alias + 1`). Other engine entry points (`ngx_http_complex_value` 60-107, `regex_start_code` 1180-1246, `complex_value_code` 1838-1872) set `e->end` to the exact allocation.
- `src/http/ngx_http_variables.c`: `headers_internal` join (len accounting with `p == end` early-break), `unknown_header`, `request_line`, `argument`, `cookie`, `realpath_root`, `request_body`, `binary_remote_addr`, `host` - all consistent with upstream.

Media / range:
- `src/http/modules/ngx_http_mp4_module.c` (entire file read): `read_atom` checks `atom_size` against `NGX_MAX_OFF_T_VALUE - offset` and the enclosing `end`; moov bounded by `mp4_max_buffer_size`; every table atom (`stts/stss/ctts/stsc/stsz/stco/co64`) checks `header + entries*sizeof(entry) <= atom_data_size` in 64-bit before computing `atom_end`; `update_stsz/stco/co64` contain the CVE-2022-41741/41742 checks (`start_sample >= entries`, `end_sample - start_sample > entries`, `start_chunk >= chunks`, `end_chunk > chunks`, chunk_offset + samples_size vs `mp4->end` and `NGX_MAX_UINT32_VALUE`); `crop_stsc_data` has the `samples == 0` / `chunk == 0` guards; `crop_stts_data` cannot divide by zero (`start_time < count*duration` false when duration==0); key-frame `entry--` rewind bounded by `key_prefix <= start_sample`; `?start=`/`?end=` parsed via `ngx_http_mp4_atofp` with cutoff checks and `start < 0` -> 0.
- `src/http/modules/ngx_http_flv_module.c`: `start` via `ngx_atoof`, rejected if `>= len`.
- `src/http/modules/ngx_http_range_filter_module.c`: parser uses `cutoff/cutlim` on both bounds, `size > NGX_MAX_OFF_T_VALUE - (end-start)` guard, suffix handling, `max_ranges` limit, multipart requires single in-memory buffer (`test_overlapped`), `singlepart_body` arithmetic in off_t with casts only after range checks.
- `src/http/modules/ngx_http_slice_filter_module.c`: `Content-Range` parser with cutoff checks on all three numbers, `*p == '\0'` termination relies on NUL-terminated header values; `get_start` rejects multi-range and suffix; `ctx->start` overflow guard.

Filters:
- `ngx_http_sub_filter_module.c` (`parse`, `match`, `body_filter`, `output`): `saved`/`looked` buffers sized `max_match_len - 1`, negative offsets only index into `looked` by `-start <= looked.len`; identical to upstream.
- `ngx_http_ssi_filter_module.c`: parser guards (`NGX_HTTP_SSI_COMMAND_LEN`, `NGX_HTTP_SSI_PARAM_LEN`, `value_len`, `NGX_HTTP_SSI_MAX_PARAMS`), `evaluate_string` in-place unquoting never grows, `regex_match` captures array `(captures+1)*3`, `echo` escape length accounting, `date` strftime bounded.
- `ngx_http_addition_filter_module.c`, `ngx_http_charset_filter_module.c` (`recode_from_utf8`/`to_utf8` buffer growth with `NGX_HTML_ENTITY_LEN`/`ctx->length` headroom, `saved[NGX_UTF_LEN]` bounded by `ngx_min`), `ngx_http_gunzip_filter_module.c` (zlib buffers bounded by `gunzip_buffers`, `inflateReset` loop), `ngx_http_image_filter_module.c` (`image_read` enforces `ctx->length` = Content-Length/`image_filter_buffer`, JPEG scan `last = image + length - 10` keeps `p[7]` in bounds, GIF/PNG/WebP minimum-length checks), `ngx_http_xslt_filter_module.c` (`xslt_params` works on NUL-terminated copies).

Other modules:
- `ngx_http_autoindex_module.c` `html`/`json`: length pass accounts for `escape`, `escape_html`, `utf_len`, `NGX_HTTP_AUTOINDEX_NAME_LEN`, with `NGX_MAX_SIZE_T_VALUE` overflow guards.
- `ngx_http_dav_module.c`: Destination parsing relies on NUL-terminated header values; `validate_paths` indexes (`dst->data[len]`, `src->data[dst->len]`) are within the NUL-terminated buffers; `merge_slashes` shrinks in place; `copy_tree_file/copy_dir` allocate `copy->path.len + path->len + 1`; the recent commit 2b84cd7 correctly restores `r->uri` on the error path (no lifetime issue - `duri` points into the header value in `r->pool`).
- `ngx_http_userid_filter_module.c`: 22-char base64 -> exactly 16 bytes into `uid_got[4]`.
- `ngx_http_secure_link_module.c`: `val.len > 24` guard before base64url decode into `hash_buf[18]`; legacy variant requires exactly 32 hex chars.
- `ngx_http_upstream_sticky_module.c` (NEW): SID copied into `sn->sid[NGX_HTTP_UPSTREAM_SID_LEN]` comes only from config (`server ... sid=` validated <= `NGX_HTTP_UPSTREAM_SID_LEN` at `ngx_http_upstream.c:6665`) or a hex md5 of exactly `NGX_HTTP_UPSTREAM_SID_LEN`; request-controlled session id only feeds MD5; `stp->request` lifetime is `r->pool`; slab exhaustion handled by LRU expiry; shared-zone work under `shpool->mutex`.
- `ngx_http_geoip_module.c` (NEW MMDB path): `ngx_http_geoip_str()` copies `entry_data.data_size` bytes; v4-mapped `sin` is a stack local used only within the call; `MMDB_lookup_sockaddr` errors handled; `%.4f` into `NGX_INT64_LEN + 5` fits the worst case produced by `ngx_vslprintf` (see notes).

Core:
- `src/core/ngx_string.c`: `ngx_vslprintf`/`ngx_sprintf_num` (bounded by `last`), `ngx_atoi/atofp/atosz/atoof/atotm/hextoi` (cutoff checks), `ngx_decode_base64_internal` (`len % 4 == 1` reject, tail handling), `ngx_utf8_decode` (`n - 1 < len` incomplete check), `ngx_utf8_cpystrn`, `ngx_escape_uri` (NULL-dst counting), `ngx_unescape_uri` (REDIRECT re-emits 3 bytes for 3 consumed, in-place safe), `ngx_escape_html`, `ngx_escape_json` - all equal to upstream.
- `src/core/ngx_hash.c` (`find`, `find_wc_head/tail`, `init`, `wildcard_init`), `ngx_array.c` (`push`, `push_n`), `ngx_buf.c` (`chain_add_copy`, `update_chains`, `coalesce_file`, `update_sent`), `ngx_output_chain.c` (`align_file_buf`, `get_buf`, `copy_buf` with `ngx_min(size, dst->end - dst->pos)`), `ngx_palloc.c`, `ngx_slab.c` (`alloc_locked`/`free_locked` with pool-bounds, alignment and double-free checks) - equal to upstream.
- `src/core/ngx_resolver.c`: `process_response` validates header, question name walk (no compression allowed), `i + sizeof(qs) + nan*(2+sizeof(an)) <= n`; `process_a/srv/ptr` answer walks bounded by `n`, `i + sizeof(an) >= n` short check, A/AAAA RDATA length and `i+4/16 > n` checks, SRV `i + 6 >= n`; `ngx_resolver_copy` limits compression pointer hops to 128 and checks `p >= last` after every hop, second pass only after validation; `ngx_resolver_export` indexes bounded by `naddrs`; TCP read buffer `2 + 65535` with length-prefix loop; UDP buffer 4096 on stack with `n` passed through; SRV follow-up names copied by length.
- `src/http/ngx_http_file_cache.c`: `read` checks `n >= header_start`, version, crc32, `header_start`, key bytes, `body_start <= c->body_start`, `vary_len <= NGX_HTTP_CACHE_VARY_LEN`; `set_header` truncates etag/vary to the fixed fields; `vary`/`vary_header` normalize within `buf[NGX_HTTP_CACHE_VARY_LEN]` bounded by `len`; `reopen`/`update_variant` node refcount handling consistent with upstream.
- `src/http/ngx_http_upstream.c`: `process_header` reads into `u->buffer` of `buffer_size`, `last == end` -> "too big header"; cache `header_start + 256 > buffer_size` rejected (911); `process_headers` after commit adf76b2 returns NGX_ERROR/NGX_DONE instead of finalizing before the cleanup handler is installed (verified both call sites 2644-2656 and 1136-1143); `process_early_hints` bounds accumulated hints by `buffer_size` and `ngx_movemem`s the remainder correctly; `non_buffered_filter` clamps to `u->length`; `rewrite_location`, `process_trailers` fine.
- `src/event/ngx_event_pipe.c`: `read_upstream` (buffer allocation bounded by `bufs.num`, `free_raw_bufs` partial-buffer handling, `p->length` clamping in `copy_input_filter`), `write_chain_to_temp_file` (size/`max_temp_file_size` accounting, shadow bookkeeping), `add_free_buf`, `remove_shadow_links`, `drain_chains` - equal to upstream.

## Low-priority notes

- JSON parser streaming API (`ngx_json_parse_ctx` with per-call `start = NULL`): if a future caller feeds a document in several chunks, a string or number spanning a chunk boundary would be emitted with `start == NULL` (`p - start` huge). Not reachable: the only caller passes the whole value in one call. Worth a comment/assert.
- `ngx_http_geoip_module.c` MMDB float path: `ngx_sprintf(v->data, "%.4f", value)` with a DB-supplied double >= 2^63 performs an out-of-range `(int64_t)` cast in `ngx_vslprintf` (UB, in practice INT64_MIN -> 19 digits, still fits `NGX_INT64_LEN + 5`). Legacy GeoIP path had the same pattern; DB is operator-controlled.
- `ngx_http_json_module`: a `json_set` source such as `$request_body` is parsed on every variable evaluation per request (cached per request via module ctx); worst case is linear in body size and bounded by `client_max_body_size`/`client_body_buffer_size` - no amplification.
- `ngx_http_upstream_sticky_module`: request-controlled `lookup`/`create` variable values create slab nodes bounded by zone size with LRU eviction (`sess_expire(sess, 1)`); SID strings are config-only.
- `ngx_resolver_process_ptr`: `ngx_strcasecmp(&buf[i], "\7in-addr\4arpa")` scans for NUL within the 4096-byte stack buffer; the question name was NUL-terminated by `process_response` before reaching here, so the scan is bounded (same as upstream).

## Limitations

- The ASan nginx binary lacks `ngx_http_json_module`, so the HTTP consumer was tested only by static analysis; the core parser/unescaper were fuzzed in a standalone ASan/UBSan harness (3M parses with container/key skips, plus mutation fuzzing and 50 fixed edge cases).
- `ngx_http_ssi_filter_module.c` was reviewed in its parser, evaluate/echo/include/set/regex paths; the block/config/if directive handlers and `ngx_http_ssi_output` were not read line by line.
- `ngx_http_upstream.c` (7.4k lines) was reviewed in the header/buffer-handling paths listed above; the request-body sending, keepalive/next-upstream and cache-send state machines were not re-read.
- `src/os/unix/ngx_control.c` uses the JSON *renderer* only (output), judged out of scope.
- No dynamic tests were run against the mp4/range/resolver code paths; conclusions there rest on static comparison with upstream.
