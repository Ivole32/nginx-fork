# Agent B2 report — QUIC transport, mail/stream protocols, resource exhaustion/concurrency

Repo: /home/user/nginx-fork @ b38c9d8068ab55504aa4311f729803b503579520 (1.31.8 dev)

## Key framing fact (affects confidence of everything below)
I fetched the matching upstream commit b38c9d80 from github.com/nginx/nginx and
diffed the entire `src/` tree against the fork:

    diff -rq <upstream b38c9d80>/src /home/user/nginx-fork/src   # no content differences

The fork is **byte-identical to upstream nginx** for every file in my scope (and all
of src/). There are no fork-introduced changes to review. This is therefore an audit
of stock, mature, heavily-reviewed nginx code. I found no new high-confidence defects;
the items below are low-confidence / informational, with mitigations noted.

## Candidates
None rated Medium or High. All suspected weaknesses I examined are defeated by an
existing bound, validation, or config default (detailed in "Areas reviewed").

## Low-priority notes

- DOS-1 (Low, informational): Out-of-order STREAM/CRYPTO buffering granularity.
  src/event/quic/ngx_event_quic_streams.c `ngx_quic_write_buffer()` /
  `ngx_quic_alloc_buf()` store received data in fixed 4096-byte buffers
  (NGX_QUIC_BUFFER_SIZE) and create "hole" buffers for gaps. A client that sends
  1 data byte at each 4096-aligned offset forces a full 4096-byte buffer per byte,
  i.e. ~4096x memory amplification over bytes-on-wire. BUT this is bounded two ways:
  per-stream flow control `qs->recv_max_data` (= stream_buffer_size, default 64k for
  HTTP/3) enforced in `ngx_quic_control_flow()` before `ngx_quic_write_buffer()`, the
  connection-wide `recv_max_data` (= initial_max_data), and the global
  `qc->max_frames` flood cap plus the datagram "quic flood detected" check in
  `ngx_quic_handle_datagram()` (ngx_event_quic.c: `(c->sent + qc->received)/8 >
  (streams.sent + streams.recv_last) + 1048576`). CRYPTO is additionally capped at
  NGX_QUIC_MAX_BUFFERED = 65535 (ngx_event_quic_ssl.c). Memory is bounded per
  connection; not a practical amplification beyond configured limits. Worth a note
  only.

- Note: QUIC amplification limit is enforced (ngx_quic_path_limit(), 3x received
  before path validation) and PATH_CHALLENGE/PATH_RESPONSE/retry paths all respect
  it. ngx_quic_send_stateless_reset() is rate-limited per source via a per-second
  65536-byte bitmap (3 hashes) — bounded and self-resetting.

- Note: Stateless-reset bitmap `static uint8_t bitmap[65536]` is per-worker global
  state shared across all clients; collisions only cause occasional suppression of a
  stateless-reset packet (fail-safe), no correctness/security impact.

## Areas reviewed with no issue found

QUIC transport / framing (src/event/quic/ngx_event_quic_transport.c):
- `ngx_quic_parse_int` bounds `len = 1<<(*p>>6)` against `end` before reading; all
  frame field reads use parse_int / read_uint8/32 / read_bytes / copy_bytes with
  `end` checks. No OOB read.
- `ngx_quic_copy_bytes` targets are fixed arrays guarded by prior length checks:
  NEW_CONNECTION_ID len validated `>=1 && <=20` before copy into cid[20]; SR token is
  fixed 16; PATH_CHALLENGE/RESPONSE copy exactly 8 into data[8]. No fixed-buffer
  overflow.
- Long/short header parse (`ngx_quic_parse_long_header`): dcid/scid lengths bounded
  by NGX_QUIC_CID_LEN_MAX (20); token length read then bytes bounded by `end`.
- `NEW_CONNECTION_ID` retire>seqnum rejected; MAX_STREAMS / STREAMS_BLOCKED limits
  capped at 0x1000000000000000; frame type > NGX_QUIC_FT_LAST rejected;
  `ngx_quic_frame_allowed()` enforces per-packet-type frame permission table.
- `ngx_quic_parse_transport_params`: length-prefixed, `end-p < len` checked;
  forbidden server-only TPs rejected; trailing-garbage rejected.

QUIC ACK (ngx_event_quic_ack.c):
- `ngx_quic_handle_ack_frame` validates first_range<=largest, each gap+2<=min,
  range<=max — prevents negative/computed-underflow PNs (FRAME_ENCODING_ERROR).
- Received ranges iterated `range_count` times reading from the frame buffer bounds;
  stored ACK ranges capped at NGX_QUIC_MAX_RANGES (10) in `ngx_quic_ack_packet`.
- Loss detection / PTO timers and congestion math reviewed; no unbounded loops
  (Newton iteration fixed at 10). `ngx_quic_congestion_ack/lost` guard plen==0 and
  pnum<rst_pnum.

QUIC streams (ngx_event_quic_streams.c):
- Stream creation in `ngx_quic_get_stream` loops min_id..id bounded by
  client_max_streams_{uni,bidi} (STREAM_LIMIT_ERROR beyond); each stream limited by
  config max_concurrent_streams.
- UAF surface: closed streams removed from rbtree and recycled to streams.free;
  later frames resolve to NGX_QUIC_STREAM_GONE (id < client_streams) and are no-ops.
  `ngx_quic_close_streams` posts read events then re-checks tree; cleanup handler
  nulls qs->connection before close_stream.
- Flow control accounting (`ngx_quic_control_flow`/`update_flow`) enforces per-stream
  and connection recv_max_data; FINAL_SIZE_ERROR checks on fin/reset consistent.
- `ngx_quic_handle_stream_frame`: `last = off+len` noted 62-bit (no overflow); data
  copied into owned buffers, stack chain/buf only referenced during copy.

QUIC connid / migration / socket / udp (connid.c, migration.c, socket.c, udp.c):
- nclient_ids checked against active_connection_id_limit → CONNECTION_ID_LIMIT_ERROR;
  retire handling honors max_retired_seqnum monotonicity; RETIRE of DCID-in-use and
  never-issued seqnum rejected (PROTOCOL_VIOLATION).
- server IDs capped NGX_QUIC_MAX_SERVER_IDS (8) ∧ ctp.active_connection_id_limit.
- Migration only acts on highest-numbered non-probing packet; path validation uses
  random challenge, retries bounded NGX_QUIC_PATH_RETRIES; reverts to backup path.
- recvmsg loops use fixed static buffer NGX_QUIC_MAX_UDP_PAYLOAD_SIZE; socklen
  clamped to sizeof(ngx_sockaddr_t); unbound AF_UNIX dropped.

QUIC output (ngx_event_quic_output.c): packet build bounds payload via
ngx_quic_payload_size and max_payload; split_frame handles oversize; static dst/src
buffers sized to max UDP payload; segment count capped NGX_QUIC_MAX_SEGMENTS (64).

QUIC BPF (ngx_event_quic_bpf.c): map inherit/export parsing over env var; worker
index bounds checked (`ngx_worker >= grp->listening.nelts` → error) before indexing.

Mail parsers (ngx_mail_parse.c): POP3/IMAP/SMTP state machines bound args
(nelts<=2 / <=10), tag length (<=31), IMAP literal_len overflow guarded
(`> NGX_MAX_SIZE_T_VALUE/10`); literal data bounded by client_buffer_size (over-long
→ "too long command", quit). Backslash-unescape operates in-place within the arg,
no overread. Non-sync literal abuse (`{n+}`) detected and connection quit.

Mail handlers / auth (ngx_mail_handler.c, *_handler.c): base64 decode sizes via
ngx_base64_decoded_length; AUTH PLAIN/LOGIN/CRAM-MD5/EXTERNAL parse decoded buffers
with explicit bounds; max_errors caps invalid commands; read_command caps buffer.

Mail auth_http (ngx_mail_auth_http_module.c): client login/passwd escaped with
ngx_escape_uri(NGX_ESCAPE_MAIL_AUTH) (escapes CR/LF/%/control) before Auth-User/
Auth-Pass headers — no request-splitting into the auth server. Auth-SMTP-Helo/From/To
cannot contain CRLF (parser splits on CR/LF). Backend login/passwd ultimately come
from the (trusted) auth server's Auth-User/Auth-Pass response.

Mail proxy (ngx_mail_proxy_module.c): USER/PASS/LOGIN/AUTH lines built from
s->login/s->passwd (post-auth_http values) and server_name; IMAP uses literal
syntax ({len}) so login/passwd bytes aren't line-parsed by upstream; upstream
response parsing requires trailing CRLF and bounds on buffer (too-long → error).

Stream (ngx_stream_handler.c, ngx_stream_proxy_module.c, ngx_stream_limit_conn_module.c):
- UDP session proxying bounds responses/requests via pscf; buffers fixed to
  pscf->buffer_size; `ngx_delete_udp_connection` on finalize for request-limited
  sessions; shutdown path checks ngx_terminate/ngx_exiting for DGRAM.
- limit_conn shared-zone: key len capped 255; node alloc under shpool->mutex;
  conn counter u_short incremented under lock, decremented in pool cleanup under lock;
  lock released on every error path (verified cleanup_all + each early return).

Concurrency / core (ngx_shmtx.c, ngx_rwlock.c, ngx_thread_pool.c, ngx_event_accept.c,
ngx_event_timer.c, ngx_event_posted.c, ngx_slab.c, ngx_process_cycle.c):
- shmtx/rwlock: standard spin+sem / CAS; unlock paths balanced; accept-mutex
  released on EMFILE/ENFILE and in trylock failure path.
- thread_pool: max_queue enforced (overflow → NGX_ERROR, no unbounded growth);
  done-queue spinlock balanced with memory barriers; task.event.active reuse guarded.
- worker shutdown/drain: ngx_exiting + ngx_event_no_timers_left + close_idle +
  shutdown timer; no obvious leak/hang. Timers rbtree, posted-events queue sound.

## Limitations
- I did NOT re-derive the correctness of the QUIC crypto/token/protection code
  (out of scope: _protection.c, _ssl.c crypto, _tokens.c) — I relied on their
  interfaces (keys_available, decrypt, new/validate_token) behaving as named.
- No dynamic testing was performed: an ASan build exists at build-asan/nginx but,
  given the tree is byte-identical to released nginx and I found no concrete
  trigger, I did not construct fuzz/PoC inputs. A validator wanting extra assurance
  could fuzz ngx_quic_parse_frame / ngx_mail_*_parse_command under ASan.
- I reviewed BPF C glue but not the eBPF bytecode object (ngx_event_quic_bpf_code.c
  is generated) for verifier-level issues.
