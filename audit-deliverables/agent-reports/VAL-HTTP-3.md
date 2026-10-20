# VAL-HTTP-3 — Independent validation of Agent B finding HTTP-3

Validator: Agent F. Role: disprove / re-scope. Repo @ b38c9d8 (1.31.8 dev).
ASan build: `/tmp/.../scratchpad/build-asan/nginx` — present, `nginx -V` confirms
`--with-http_v2_module` (grpc is built in with it) and the fork's separate
`ngx_http_proxy_v2_module.c` is in `src/http/modules/`.

## Conclusion

**Robustness / interoperability gap — mechanism CONFIRMED, but the "asymmetry"
framing is re-scoped (partially disproved). NOT a security defect; no smuggling.**

Agent B's rating (Low, no smuggling) stands and is, if anything, generous. The
forwarding behaviour is real and reproduced on the ASan build, but the claimed
asymmetry is *not* internal to nginx: nginx accepts the same lenient value byte set
on h1, h2 **and** h3 inbound, so it is self-consistent. The gap is only between
nginx-as-sender (deliberately permissive, which RFC 9113 §8.2.1 explicitly allows a
sender to be) and a *strict receiving* h2 peer. It is long-standing upstream
behaviour (the grpc module has shipped it for years), mirrored byte-for-byte by the
fork's proxy_v2 module.

## Evidence

### 1. Parser behaviour — CONFIRMED (static)

`src/http/ngx_http_parse.c`:
- `sw_space_before_value` (1026-1049): only `case ' '` is consumed as leading OWS.
  HTAB (0x09) and every other non-SP byte hit `default:` → `header_start = p;
  state = sw_value;` → **leading HTAB becomes part of the value.**
- `sw_value` (1051-1067): switch handles only `' '`, `CR`, `LF`, `'\0'`. `' '` →
  `sw_space_after_value`; CR/LF end the value; NUL → `NGX_HTTP_PARSE_INVALID_HEADER`.
  **Every other byte (0x01-0x08, 0x09 HTAB, 0x0B, 0x0C, 0x0E-0x1F, 0x7F, 0x80-0xFF)
  falls through with no case and stays in the value.**
- `sw_space_after_value` (1071-1086): only `case ' '` is treated as trailing OWS
  (and `header_end` was already pinned before the SP in `sw_value`). A trailing HTAB
  is never seen here, so **trailing HTAB is not trimmed.**

So nginx trims only SP for OWS and rejects only NUL/CR/LF in values — exactly the
claim. (RFC 9110 OWS = SP / HTAB; nginx under-trims by ignoring HTAB. That is the
real, narrow spec deviation.)

### 2. Inbound h2/h3 validators — nginx itself is equally lenient (re-scopes the claim)

`ngx_http_v2_validate_header` (`src/http/v2/ngx_http_v2.c:3284`) and
`ngx_http_v3_validate_header` (`src/http/v3/ngx_http_v3_request.c:705`) are
byte-identical for values:

```c
for (i = 0; i != value.len; i++) {
    ch = value.data[i];
    if (ch == '\0' || ch == LF || ch == CR) { ...return NGX_ERROR; }
}
```

They reject **only** NUL/LF/CR — the same set as h1. (Names are strict: `ch <= 0x20
|| 0x7f || ':' || A-Z` rejected; but that is names, not values.) Therefore nginx
accepts leading/trailing HTAB, 0x01-0x08, 0x0B, 0x0C, 0x7F in values on **all three**
protocols. There is no intra-nginx asymmetry; nginx is a consistently permissive
sender/receiver. Confirmed empirically (§5).

### 3. proxy_v2 / grpc outbound encoding — no validation/trim (CONFIRMED static)

`ngx_http_proxy_v2_module.c` pass_request_headers loop (862-867):
```c
*b->last++ = 0;
b->last = ngx_http_v2_write_name(b->last, header[i].key.data, header[i].key.len, tmp);
b->last = ngx_http_v2_write_value(b->last, header[i].value.data, header[i].value.len, tmp);
```
`header[i].value` is written verbatim; no OWS trim, no C0/DEL rejection.
`ngx_http_grpc_module.c` has the identical loop (pass at :889, write_value at
:1001/1030/1054/1061). A grep for any outbound value sanitising (`0x7f|0x09|htab|
trim|ows|\t|iscntrl`) in both modules returns only *response-side* (inbound-from-
upstream) parsing hits (name validator at proxy_v2:3394 / grpc:3569; HPACK field-len
at 3080/3199/3259/3378). So there is no outbound value validation anywhere.

### 4. No smuggling / no framing injection — CONFIRMED (code + capture)

`ngx_http_v2_string_encode` (`src/http/v2/ngx_http_v2_encode.c:17-40`) writes an
explicit HPACK length (via `ngx_http_v2_write_int`, 7-bit prefix) then copies the
bytes (`ngx_cpymem`) or the huffman output. Length is explicit; there is no
delimiter. A value byte therefore cannot create a header boundary, extend the field,
or alter frame framing. The HEADERS frame length is set from `b->last - headers_frame`
afterwards (proxy_v2:884-898), independent of value content. No injection path.

### 5. Dynamic reproduction on the ASan build — CONFIRMED

Config (`val-http3/nginx.conf`): `location / { proxy_pass http://127.0.0.1:18950;
proxy_http_version 2; }` (verified `proxy_http_version 2` selects the proxy_v2
handler: `ngx_http_proxy_module.c:199` enum `"2"→NGX_HTTP_VERSION_20`, dispatch at
:889-890). Raw Python TCP server on 18950 (no h2 lib) dumps hex of what nginx sends.

Client sent over h1: `X-T: \tv\t` and `X-C: a\x0bb`. Captured HPACK (from
`val-http3/srv.out`):

```
...0000 2201 0500 0000 01 82 86 84 41 8b...   # HEADERS len=0x22 flags=0x05 sid=1
...00 03 78 2d 74   03 09 76 09               # name "x-t" (len3), value len3 = 09 'v' 09
...00 03 78 2d 63   03 61 0b 62               # name "x-c" (len3), value len3 = 'a' 0b 'b'
```
REPR excerpt: `...\x00\x03x-t\x03\tv\t\x00\x03x-c\x03a\x0bb`

So the HPACK literal carries `x-t = <HTAB> v <HTAB>` (leading **and** trailing HTAB
preserved, untrimmed) and `x-c = a <0x0B> b` (embedded VT preserved), each with an
explicit RAW length of 0x03. Exactly as claimed.

nginx returned `502 Bad Gateway` to the client — but **only because my raw server
is not a real h2 endpoint** (it dumped bytes and closed). This 502 is NOT evidence
that a strict peer rejects the bytes; it is a test artifact. The load-bearing
evidence is the captured bytes, which are forwarded unchanged.

Consistency check (nginx as h2 server, `listen 127.0.0.1:18901 http2`, curl
`--http2-prior-knowledge`, nghttp2 1.59):
```
X-C: a\x0bb   -> HTTP 200
X-T: \tv\t    -> HTTP 200
```
nginx accepts both over inbound h2, confirming §2. (A very common upstream — nginx
itself — therefore would NOT reject these values, which further lowers real impact.)

Commands: `val-http3/h2srv.py`, `val-http3/client.py`, `val-http3/nginx.conf`; run
log reproduced above. All on loopback 18900/18901/18950; nginx started with
`-p <scratch> -c nginx.conf`, ASAN_OPTIONS=detect_leaks=0; no ASan/UBSan reports.

## Assessment

- **Security defect?** No. No request smuggling, no header injection, no memory
  issue (HPACK length-prefixed; explicit lengths; verbatim copy). The only party
  harmed is the attacker/client making the odd request.
- **Robustness / interop gap?** Yes, narrowly: nginx under-trims OWS (ignores HTAB)
  and forwards C0/DEL/HTAB verbatim to a strict h2 upstream, which per RFC 9113
  §8.2.1 *may* treat the message as malformed → per-request 502/RST_STREAM for that
  one request. Whether it fails at all is upstream-dependent (fails with
  nghttp2/Go/Envoy; succeeds with nginx or any equally lenient peer).
- **Expected / pre-existing?** Yes. This is stock upstream nginx grpc behaviour that
  the fork's proxy_v2 module reproduces; it is not fork-introduced.

## Severity + confidence

- Severity: **Low** (robustness/interop). Agreement with Agent B's Low rating; I
  would not raise it to a security finding. Realistic impact: self-inflicted
  per-request failure.
- Confidence: **High** that the mechanism exists (code + dynamic capture). **High**
  that there is no smuggling/injection. **High** that nginx is internally consistent
  (so the "asymmetry" is nginx-vs-strict-peer, not h1-vs-h2 inside nginx).

## Uncertainty / limitations

- I did not drive a real strict third-party h2 upstream (no h2 server lib installed);
  the 502 observed is a test artifact, so the exact "502 vs RST_STREAM vs accepted"
  outcome against, e.g., nghttpd/Go is inferred from RFC 9113 §8.2.1, not measured.
  The forwarding-of-raw-bytes half — the part that matters — is measured.
- curl/nghttp2 may itself normalise OWS on the client side in the §5 consistency
  test; the HTTP 200 still proves nginx did not reject, which is the point.
- Suggested hardening (optional, matches Agent B): trim HTAB as OWS and/or reject
  C0/DEL in the h2/grpc value writer. Low priority; would improve interop only.
