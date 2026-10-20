# GH-MEM-1: Variant analysis, remediation and regression test for MEM-1

Agent G/H report. Parent finding: MEM-1 (`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/REPORT-C-MEM.md`).
Target: `/home/user/nginx-fork/src/core/ngx_json_parse.c` (+ `ngx_json_parse.h`), revision b38c9d8068ab55504aa4311f729803b503579520.
The repository was not modified. All builds were made from copies of the two source files under
`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/orig/` (pristine) and `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/patched/` (patched), compiled with
`gcc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined` (`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/build.sh`); the clang ASan
runtime is not installed on this host. Every output quoted below is a real run; raw logs are in `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/*.txt`.

## 0. Summary

- Root cause confirmed and generalised: the skip state (`ctx->skip_until_depth`) is cleared *lazily*, at the
  top of the byte loop (`ngx_json_parse.c:89-99`), only once the parser is in a separator/done state at
  `depth <= skip_until_depth` and only if a next byte exists. `ngx_json_close()` (`:791-807`) decrements `depth`
  and emits the CLOSE while the skip is still armed, so the CLOSE of the container at exactly
  `skip_until_depth` is *always* suppressed. That is correct for OPEN/KEY skips (the consumer never saw that
  container's OPEN) and wrong for scalar-element skips (the consumer did see the array's OPEN). Both origins
  store the same value in `skip_until_depth` (the depth *outside* the container), so they cannot be told apart
  at close time with the existing fields; a one-bit flag is required.
- 26 hand-built variants traced on both builds (`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/variants.sh`): 12 are defects (the whole
  scalar-in-array family, incl. nested / last-element / end-of-input shapes), 14 are consistent (all KEY,
  container-OPEN, object-member-value, top-level-scalar and CLOSE-skip shapes). The chunk-boundary
  `start == NULL` note is a separate latent API hazard, unrelated to skipping and unreachable in-tree.
- Grep confirms `src/http/modules/ngx_http_json_module.c` is the only in-tree consumer; it returns
  `NGX_JSON_SKIP` only on container OPEN (`:726`) and KEY (`:786`), never on `VALUE_*`, and never reads
  `jctx` after `ngx_json_parse_ctx()` returns (`:346`), so the trailing-residue variants cannot affect it either.
- Fix: 16-line patch (`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/patches/MEM-1.diff`) adding `ctx->skip_close`; `ngx_json_close()` clears the skip
  before emitting the CLOSE when the skip originated from a scalar array element. With it: the repro delivers
  `ARR_CLOSE`; the unmodified `memc/json_harness.c` and a strengthened copy pass 5 seeds x 500k iterations
  (1M parses per seed) with scalar skips enabled under ASan/UBSan; the same runs abort on the unpatched copy on
  every seed; a differential trace of 3 x 400k parses with container/key skips only (what the HTTP module
  does) is byte-for-byte identical between unpatched and patched; `-O2` timing is within noise.
- Regression test `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/regress.c`: 36 fixed cases; 16 fail on the unpatched parser, 0 on the patched one.

## 1. Part 1: Variant analysis

### 1.1 The general pattern

`ngx_json_parse_ctx()` keeps the skip in `ctx->skip_until_depth` (`NGX_JSON_NOT_SKIPPING` = off).
`ngx_json_emit()` (`:717-719`) suppresses *every* event while skipping. The skip is cleared only at the top of
the loop (`:89-99`), when a value at `depth <= skip_until_depth` has completed (state
`object_value_separator`, `array_value_separator` or `done`) and only when there is a *next byte* to run that
test on. Emit sites that can run while the skip is still armed although the skipped region is over:

| emit site | lines | event | consequence |
|---|---|---|---|
| `ngx_json_close()` after `ctx->depth--` | 797-799 | OBJECT_CLOSE / ARRAY_CLOSE of the container at `skip_until_depth` | suppressed. Correct for OPEN/KEY skips, **wrong for scalar-element skips** (defect) |
| loop top with no next byte | 85, 649 | none: if the skipped region ends on the last byte, the lazy clear never runs | `skip_until_depth` residue stays in `ctx` after `NGX_OK` (harmless, 1.4) |
| bare top-level number at end of input | 654-666 | VALUE_NUMBER at depth 0 | a skip can only be armed inside a container, and depth 0 with state `number_*` means no container is open, so this never runs while skipping; consistent |

How each skip origin encodes itself (`ngx_json_emit()` `:744-767`), D = depth outside the container concerned:

- OPEN skip: emitted at `ctx->depth == D` *before* `ngx_json_push_state()`, so `skip_until_depth = D`. The
  container's close brings depth back to D, `depth == skip_until_depth`, CLOSE suppressed. The consumer never
  saw the OPEN, so this is right.
- KEY skip: `skip_until_depth = D` where D is the depth *inside* the object. Scalar member value: state becomes
  `object_value_separator` at depth D and the next byte (`,` or the closing brace) clears the skip at loop top
  before the brace is processed, so the object's own CLOSE is delivered. Container member value: its close brings
  depth back to D, suppressed (right, its OPEN was suppressed), and the next byte clears. Consistent in every shape.
- Scalar array-element skip: emitted at `ctx->depth == D+1`, `skip_until_depth = D` (`:761`). The array's `]`
  brings depth to D, `depth == skip_until_depth`, ARRAY_CLOSE suppressed. **The consumer saw this array's
  OPEN**, so the stream is unbalanced. Same encoding as an OPEN skip of that same array, hence
  indistinguishable at close time.

### 1.2 Variant table

Delivered event lists are as printed by `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/trace.c`, a consumer that checks: every delivered OPEN gets a
delivered CLOSE, a delivered KEY is followed by a value/OPEN, CLOSE types match the consumer's stack, and
residue in `ctx` after return. Verdicts are for the UNPATCHED parser. Residue = `ctx->skip_until_depth !=
NOT_SKIPPING` after `NGX_OK`. Encoding: `{ }` object open/close, `[ ]` array open/close, `K:` key, `S:` string,
`N:` number, `B:` bool, `Z` null, `!` = handler returned SKIP on that event.

| id | input | handler | delivered events (unpatched) | residue | verdict |
|---|---|---|---|---|---|
| V0 | `{"a":[1,2],"b":3}` | SKIP on NUM `1` | `{ K:a [ N:1! K:b N:3 }` (no `]`) | no | **Defect** (parent) |
| V1 | `{"a":[1,2]}` | SKIP on NUM `1` | `{ K:a [ N:1! }` | no | **Defect** |
| V2 | `[1,2]` | SKIP on NUM `1` | `[ N:1!` | **yes** | **Defect** + residue |
| V2b | `[1]` (`]` is the very next byte) | SKIP on NUM `1` | `[ N:1!` | **yes** | **Defect** + residue |
| V2c | `[1]  ` (trailing ws) | SKIP on NUM `1` | `[ N:1!` | no (ws cleared it) | **Defect** |
| V3 | `[0,[1,2]]` (skipped array is last element of outer) | SKIP on NUM `1` | `[ N:0 [ N:1! ]` (outer `]` delivered, inner lost; consumer pops the wrong frame) | no | **Defect** |
| V3b | `[[1,2]]` | SKIP on NUM `1` | `[ [ N:1! ]` | no | **Defect** |
| V3c | `{"a":[[1],[2]],"b":[3]}` | SKIP on NUM `1` | `{ K:a [ [ N:1! [ N:2 ] ] K:b [ N:3 ] }` (inner `]` lost; later closes shift by one; `K:b` arrives with an array frame on top) | no | **Defect** |
| V4 | `[1,{"x":2},3]` | SKIP on NUM `1` | `[ N:1!` | **yes** | **Defect** + residue |
| V4b | `[1 ]` | SKIP on NUM `1` | `[ N:1!` | **yes** | **Defect** + residue |
| V5 | `["x","y"]` | SKIP on STR `x` | `[ S:x!` | **yes** | **Defect** + residue |
| V5b | `[true,null]` | SKIP on BOOL `true` | `[ B:true!` | **yes** | **Defect** + residue |
| V6 | `{"a":1,"b":2}` | SKIP on NUM `1` (object member value) | `{ K:a N:1! K:b N:2 }` (ignored by design, `:739-741`) | no | Consistent |
| V7 | `{"a":1,"b":2,"c":3}` | SKIP on KEY `b` | `{ K:a N:1 K:b! K:c N:3 }` | no | Consistent |
| V7b | `{"a":1,"b":2}` KEY skip on last member, scalar value, then `}` | SKIP on KEY `b` | `{ K:a N:1 K:b! }` | no | Consistent |
| V7c | `{"a":1,"b":{"c":[1]}}` KEY skip, container value, then `}` | SKIP on KEY `b` | `{ K:a N:1 K:b! }` | no | Consistent |
| V7d | `{"o":{"b":1}}` KEY skip in nested object that is the last member | SKIP on KEY `b` | `{ K:o { K:b! } }` | no | Consistent |
| V7e | `{"a":1}` KEY skip on the only member, end of input after `}` | SKIP on KEY `a` | `{ K:a! }` | no | Consistent |
| V8 | `[[1],2]` | SKIP on 2nd ARR_OPEN | `[ [! N:2 ]` | no | Consistent |
| V8b | `[0,[1]]` container skip, last element | SKIP on 2nd ARR_OPEN | `[ N:0 [! ]` | no | Consistent |
| V8c | `{"a":{"x":1},"b":2}` | SKIP on 2nd OBJ_OPEN | `{ K:a {! K:b N:2 }` | no | Consistent |
| V9 | `{"a":1}` container skip at top level, end of input immediately (`ngx_json_done`) | SKIP on OBJ_OPEN | `{!` | **yes** | Consistent (residue only; harmless, 1.4) |
| V9b | `{"a":1} ` same with trailing whitespace | SKIP on OBJ_OPEN | `{!` | no (cleared in `done` state) | Consistent |
| V10 | `1` top-level scalar | SKIP on NUM `1` | `N:1!` (no skip armed: `depth == 0` guard `:758`) | no | Consistent |
| V10b | `"x" ` | SKIP on STR `x` | `S:x!` | no | Consistent |
| V11 | `[[1],2]` | SKIP on ARR_CLOSE | `[ [ N:1 ]! N:2 ]` (ignored, `default:` `:765`) | no | Consistent |
| C1 | `{"a":"xy` + `z"}` fed in two `ngx_json_parse_ctx()` calls | none | 2nd call delivers VALUE_STRING with `token.data=(nil)`, `token.len=94000386396481` | n/a | Not applicable (separate latent API hazard, unreachable in-tree, 1.5) |

Additional shapes folded into the regression test (section 3) and the fuzz runs: escaped-string element skip
(`["aA",1]`), null element skip, two consecutive scalar skips in sibling arrays (`[[1,2],[3,4]]`, checks
the flag is re-armed and cleared correctly), scalar skip as the last element of the outer array after an inner
skip (`[[1,2],[3,4],5]`), escaped KEY skip, container skip whose body contains nested arrays. The scalar ones
are defects on the unpatched parser, all others consistent.

### 1.3 Full traces for the key variants (unpatched, then patched)

Parent (V0):

```
--- V0  parent: scalar skip in array, array mid-object
input: {"a":[1,2],"b":3}   rule: skip NUM "1" #1
  depth=0 OBJ_OPEN  "{"
  depth=1 KEY       "a"
  depth=1 ARR_OPEN  "["
  depth=2 NUM       "1"   <- handler returns NGX_JSON_SKIP
  depth=1 KEY       "b"
  !! KEY outside object
  depth=1 NUM       "3"
  depth=0 OBJ_CLOSE "}"
  !! CLOSE type mismatch
  rc=0 ctx.depth=0 ctx.skip_until_depth=NOT_SKIPPING
  !! 1 consumer frame(s) left open at end
  verdict: INCONSISTENT
```
```
--- V0  parent: scalar skip in array, array mid-object
input: {"a":[1,2],"b":3}   rule: skip NUM "1" #1
  depth=0 OBJ_OPEN  "{"
  depth=1 KEY       "a"
  depth=1 ARR_OPEN  "["
  depth=2 NUM       "1"   <- handler returns NGX_JSON_SKIP
  depth=1 ARR_CLOSE "]"
  depth=1 KEY       "b"
  depth=1 NUM       "3"
  depth=0 OBJ_CLOSE "}"
  rc=0 ctx.depth=0 ctx.skip_until_depth=NOT_SKIPPING
  verdict: consistent
```

Nested, inner array is the last element of the outer array (V3):

```
--- V3  nested arrays: skipped scalar's array is last element of outer array
input: [0,[1,2]]   rule: skip NUM "1" #1
  depth=0 ARR_OPEN  "["
  depth=1 NUM       "0"
  depth=1 ARR_OPEN  "["
  depth=2 NUM       "1"   <- handler returns NGX_JSON_SKIP
  depth=0 ARR_CLOSE "]"
  rc=0 ctx.depth=0 ctx.skip_until_depth=NOT_SKIPPING
  !! 1 consumer frame(s) left open at end
  verdict: INCONSISTENT
```
```
--- V3  nested arrays: skipped scalar's array is last element of outer array
input: [0,[1,2]]   rule: skip NUM "1" #1
  depth=0 ARR_OPEN  "["
  depth=1 NUM       "0"
  depth=1 ARR_OPEN  "["
  depth=2 NUM       "1"   <- handler returns NGX_JSON_SKIP
  depth=1 ARR_CLOSE "]"
  depth=0 ARR_CLOSE "]"
  rc=0 ctx.depth=0 ctx.skip_until_depth=NOT_SKIPPING
  verdict: consistent
```

Skip armed on the final value, `]` is the final byte (V2b):

```
--- V2b scalar skip, single element: ']' is the very next byte
input: [1]   rule: skip NUM "1" #1
  depth=0 ARR_OPEN  "["
  depth=1 NUM       "1"   <- handler returns NGX_JSON_SKIP
  rc=0 ctx.depth=0 ctx.skip_until_depth=RESIDUE
  !! 1 consumer frame(s) left open at end
  verdict: INCONSISTENT
```
```
--- V2b scalar skip, single element: ']' is the very next byte
input: [1]   rule: skip NUM "1" #1
  depth=0 ARR_OPEN  "["
  depth=1 NUM       "1"   <- handler returns NGX_JSON_SKIP
  depth=0 ARR_CLOSE "]"
  rc=0 ctx.depth=0 ctx.skip_until_depth=NOT_SKIPPING
  verdict: consistent
```

KEY skip on the last member followed by the closing brace (V7b), unchanged by the patch:

```
--- V7b KEY skip on last member, scalar value, then '}'
input: {"a":1,"b":2}   rule: skip KEY "b" #1
  depth=0 OBJ_OPEN  "{"
  depth=1 KEY       "a"
  depth=1 NUM       "1"
  depth=1 KEY       "b"   <- handler returns NGX_JSON_SKIP
  depth=0 OBJ_CLOSE "}"
  rc=0 ctx.depth=0 ctx.skip_until_depth=NOT_SKIPPING
  verdict: consistent
```

Container skip at top level with end of input immediately after (V9), unchanged by the patch, residue in both:

```
--- V9  container skip at top level, end of input immediately
input: {"a":1}   rule: skip OBJ_OPEN "{" #1
  depth=0 OBJ_OPEN  "{"   <- handler returns NGX_JSON_SKIP
  rc=0 ctx.depth=0 ctx.skip_until_depth=RESIDUE
  verdict: consistent
```

Complete logs: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/variants-orig.txt`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/variants-patched.txt`; a `diff` of the two touches only the 12
scalar-skip variants (adds one `ARR_CLOSE` line each and removes the `!!` lines).

### 1.4 Trailing skip state (V2, V2b, V4, V4b, V5, V5b, V9)

If the skipped region ends on the last byte of the buffer, the lazy clear at `:89-99` never runs and
`ctx->skip_until_depth` is left set after `ngx_json_parse_ctx()` returns `NGX_OK`. Effect on a hypothetical
next call: none. `ngx_json_parse_ctx()` returns `NGX_DECLINED` immediately when `ctx->state == ngx_json_done`
(`:76-78`), and `ngx_json_ctx_init()` resets the field (`:47`). A chunked caller (state not `done`) carries the
skip over the boundary by design; that is what the field in `ctx` is for. `ngx_http_json_module.c` does not read
any `jctx` field after the parse (`:340-346`). For scalar skips the patch removes the residue as a side effect
(the close clears it); for a top-level container skip (V9) it remains and is harmless. Not patched (not a
defect; an optional cosmetic clear on the transition to `ngx_json_done` would be a separate change).

### 1.5 Chunk boundary / `start == NULL` (C1)

`start` is a local of `ngx_json_parse_ctx()` initialised to `NULL` per call (`:83`). A string or number that
began in a previous call is emitted in the next call with `data == NULL` and `len = p - NULL`. Reproduced with
`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/chunk.c` (unpatched; `chunk_patched` prints the same):

```
chunk 1: {"a":"xy
  event=0 token.data=0x557e2ba3d080 token.len=1
  event=4 token.data=0x557e2ba3d082 token.len=1
  rc=-5
chunk 2: z"}
  event=6 token.data=(nil) token.len=94000386396481
  event=1 token.data=0x557e2ba3d142 token.len=1
  rc=0
```

Independent of the skip logic, not changed by the patch, and unreachable in-tree because the only caller passes
the whole value in one call (`ngx_http_json_module.c:346`; `ngx_json_parse()` `:678-690`). Verdict: Not
applicable to MEM-1; keep as the low-priority note it already is (a fix would keep `start` in `ctx` as an
offset, or document single-call use).

### 1.6 In-tree consumers

```
$ grep -rn "ngx_json_parse\b\|ngx_json_parse_ctx\|ngx_json_ctx_init\|NGX_JSON_SKIP\|ngx_json_handler_pt" src auto | grep -v "^src/core/ngx_json_parse\.[ch]"
src/http/modules/ngx_http_json_module.c:10:#include <ngx_json_parse.h>
src/http/modules/ngx_http_json_module.c:340:    ngx_json_ctx_init(&jctx, r->pool);
src/http/modules/ngx_http_json_module.c:346:    rc = ngx_json_parse_ctx(&jctx, vv->data, vv->len);
src/http/modules/ngx_http_json_module.c:726:                return NGX_JSON_SKIP;
src/http/modules/ngx_http_json_module.c:786:            return NGX_JSON_SKIP;
auto/sources:46:           src/core/ngx_json_parse.h \
auto/sources:88:           src/core/ngx_json_parse.c \
```

Line 726 is inside `case NGX_JSON_OBJECT_OPEN: case NGX_JSON_ARRAY_OPEN:` (non-member element with no matching
path node); line 786 is inside `case NGX_JSON_KEY: case NGX_JSON_KEY_ESCAPED:` (unknown key). The `VALUE_*`
case (`:792-830`) only ever `break`s to `return NGX_OK`. The defect is unreachable through the HTTP module, as
the parent report states.

## 2. Part 2: Remediation

### 2.1 Why a flag is needed

At `ngx_json_close()` time, after `ctx->depth--`, both an OPEN skip of container X and a scalar skip inside
array X leave `ctx->depth == ctx->skip_until_depth`; `ctx->stack[depth]` holds X's type in both cases;
`in_key`/`escaped` are string-parser state; nothing else in `ngx_json_ctx_t` records whether the consumer saw
X's OPEN. Re-encoding the scalar skip at a different depth does not work either: `skip_until_depth = D+1`
would be cleared by the loop-top test on the very next byte (state `array_value_separator` at depth D+1),
ending the skip after one element instead of at `]`. Hence one bit, `ctx->skip_close`: "when the container at
`skip_until_depth` closes, stop skipping *before* its CLOSE is emitted".

### 2.2 The patch

`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/patches/MEM-1.diff`; applies cleanly with `patch -p1` to pristine copies of the two files (verified in
`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/applycheck/`; the repository itself was never touched, `git status` is clean):

```diff
--- a/src/core/ngx_json_parse.h
+++ b/src/core/ngx_json_parse.h
@@ -95,6 +95,7 @@
     ngx_uint_t             hex_left;         /* hex digits still expected */
 
     ngx_uint_t             skip_until_depth;
+    ngx_uint_t             skip_close;       /* unsigned skip_close:1; */
 
     ngx_pool_t            *pool;
     ngx_json_handler_pt    handler;
--- a/src/core/ngx_json_parse.c
+++ b/src/core/ngx_json_parse.c
@@ -45,6 +45,7 @@
 
     ctx->depth = 0;
     ctx->skip_until_depth = NGX_JSON_NOT_SKIPPING;
+    ctx->skip_close = 0;
     ctx->max_depth = NGX_JSON_DEFAULT_MAX_DEPTH;
 
     /* stack is allocated lazily on first push, sized to max_depth */
@@ -748,6 +749,7 @@
         case NGX_JSON_OBJECT_OPEN:
         case NGX_JSON_ARRAY_OPEN:
             ctx->skip_until_depth = ctx->depth;
+            ctx->skip_close = 0;
             break;
 
         case NGX_JSON_VALUE_STRING:
@@ -758,7 +760,13 @@
             if (ctx->depth > 0
                 && ctx->stack[ctx->depth - 1] == ngx_json_ctx_array
             ) {
+                /*
+                 * the consumer has already seen this array's OPEN, so
+                 * the skip must end at its ']' and the CLOSE be delivered
+                 */
+
                 ctx->skip_until_depth = ctx->depth - 1;
+                ctx->skip_close = 1;
             }
             break;
 
@@ -796,6 +804,22 @@
 
     ctx->depth--;
 
+    /*
+     * A skip started on a scalar array element ends at the array's own
+     * ']' (skip_until_depth is the array's depth): the consumer saw the
+     * ARRAY_OPEN, so stop skipping before the CLOSE is emitted.  A skip
+     * started on OPEN or KEY keeps suppressing the CLOSE of the container
+     * it covers, since that container's OPEN was never delivered.
+     */
+
+    if (ctx->skip_close
+        && ngx_json_skipping(ctx->skip_until_depth)
+        && ctx->depth <= ctx->skip_until_depth)
+    {
+        ctx->skip_until_depth = NGX_JSON_NOT_SKIPPING;
+        ctx->skip_close = 0;
+    }
+
     rc = ngx_json_emit(ctx, event, p, 1);
     if (rc != NGX_OK) {
         return rc;
```

### 2.3 Why it fixes the root cause

The skip is now cleared *at the container boundary* for the one skip origin whose boundary event must be
delivered, instead of lazily on the next byte. `ngx_json_close()` runs for every `]` and closing brace, so the
clear happens exactly when the array at `skip_until_depth` closes, regardless of whether a next byte exists
(fixes the V2/V2b/V4/V5 end-of-input shapes and their residue), whether whitespace precedes `]` (V4b), whether
the array is itself the last element of an outer container (V1, V3, V3b) or is followed by siblings (V0, V3c).
After the clear, `ngx_json_emit()` delivers the ARRAY_CLOSE; a `NGX_JSON_SKIP` returned on it is ignored as
before (`default:`), and the parse loop re-reads `ctx->skip_until_depth` into its local at `:649`, so the next
byte is processed unskipped. `skip_close` is written on every path that arms a skip (0 for OPEN/KEY, 1 for a
scalar element) and only read while skipping, so a stale value can never matter; no handler call happens while
skipping, so a second skip cannot be armed before the first is cleared (verified by the "repeated skips"
regression cases 15 and 16).

### 2.4 Compatibility with ngx_http_json_module

For OPEN and KEY skips `skip_close == 0`, so the new `if` in `ngx_json_close()` is false on its first operand
and the function behaves exactly as before; the loop-top clear and everything else are untouched. Evidence
beyond reasoning: the differential run in 2.6(d) feeds 3 x 400,000 parses (random valid JSON plus mutations,
nesting up to 70, `max_depth` 1..70) with only container/key skips (`maskmod=4`, the HTTP module's behaviour)
through both builds in trace mode, which prints a checksum of every delivered (event, depth, token offset,
token length) plus `rc` and final consumer stack height per parse; the outputs are identical. The struct gains
one `ngx_uint_t`; `ngx_json_ctx_t` is stack-allocated by its only consumer and initialised through
`ngx_json_ctx_init()`, so nothing else changes.

### 2.5 Performance

One predicated compare on a field already in cache, executed once per container close, and only evaluated past
its first operand when `skip_close` is set. Measured (`gcc -O2`, no sanitizers, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/json_harness2.c`, 1M
iterations = 2M parses *including* generator/mutator cost, seed 11):

```
===== perf: gcc -O2, no sanitizers, maskmod=4 (HTTP-module-style skips), 1M iters (2M parses), 3 runs each =====
orig     run 1: 0.714 user s
orig     run 2: 0.728 user s
orig     run 3: 0.756 user s
patched  run 1: 0.728 user s
patched  run 2: 0.724 user s
patched  run 3: 0.720 user s
===== perf: maskmod=8 (scalar skips enabled), patched only =====
patched run 1: 0.754 user s
patched run 2: 0.752 user s
patched run 3: 0.733 user s
```

The differences are inside run-to-run noise.

### 2.6 Test runs

(a) Existing repro `memc/skip_repro.c` rebuilt against the patched copy; `ARR_CLOSE` is now delivered at depth 1:

```
input: {"a":[1,2],"b":3}
  depth=0 event=OBJ_OPEN token="{"
  depth=1 event=KEY token="a"
  depth=1 event=ARR_OPEN token="["
  depth=2 event=NUM token="1"
  -> handler returns NGX_JSON_SKIP
  depth=1 event=ARR_CLOSE token="]"
  depth=1 event=KEY token="b"
  depth=1 event=NUM token="3"
  depth=0 event=OBJ_CLOSE token="}"
rc=0
```

The same source built against the unpatched copy (`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/bin/skip_repro_orig`) prints the parent report's
sequence: `OBJ_OPEN, KEY a, ARR_OPEN, NUM 1 (SKIP), KEY b, NUM 3, OBJ_CLOSE`, no `ARR_CLOSE`.

(b) The unmodified `memc/json_harness.c` against the PATCHED copy, scalar skips enabled (`maskmod=8`: the skip
mask is drawn from 0..7, so every mix of container/key/scalar skips), 500,000 iterations x 2 parses per seed,
ASan+UBSan with `-fno-sanitize-recover=undefined`, 5 seeds:

```
seed 1: done: ok=544321 declined=455679 error=0 exit=0
seed 2: done: ok=544595 declined=455405 error=0 exit=0
seed 3: done: ok=544423 declined=455577 error=0 exit=0
seed 4: done: ok=544671 declined=455329 error=0 exit=0
seed 5: done: ok=544550 declined=455450 error=0 exit=0
```

A strengthened copy, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/json_harness2.c` (adds: a delivered KEY must be followed by a value/OPEN before any
KEY/CLOSE; the consumer stack must be empty after `NGX_OK` *unconditionally*, where the original only checked
it when no residue was present), same parameters, PATCHED:

```
seed 1: done: ok=544321 declined=455679 error=0 exit=0
seed 2: done: ok=544595 declined=455405 error=0 exit=0
seed 3: done: ok=544423 declined=455577 error=0 exit=0
seed 4: done: ok=544671 declined=455329 error=0 exit=0
seed 5: done: ok=544550 declined=455450 error=0 exit=0
```

No ASan/UBSan report in any of these runs.

(c) The same two harnesses against the UNPATCHED copy, same seeds and parameters (they abort on the first
invariant failure; the strengthened harness trips on the fixed-input list before random generation starts):

```
seed 1:
  INVARIANT: KEY outside object (event 5, token len 11)
  input: {"\u0041\uffffc":{"d\uD83D\uDE00a" : {"og\bj":["u\\tl\uffff"],"\u0000wxa\/":[]}} , "t\r" : null , "mqkly":null}
  exit=134
seed 2:
  INVARIANT: stack 1 after NGX_OK
  input: [["o" ,
  exit=134
seed 3:
  INVARIANT: CLOSE type mismatch (event 1, token len 1)
  input: {"cog":{"l\u20ac":0e0} , "\n\uD83D\uDE00" : [null ,
  exit=134
seed 4:
  INVARIANT: KEY outside object (event 5, token len 2)
  input: {"o" : ["" ,
  exit=134
seed 5:
  INVARIANT: CLOSE type mismatch (event 1, token len 1)
  input: {"\"":{"t" : ["t\u0041v\u00e9i" ,
  exit=134
```

```
seed 1:
INVARIANT: stack 1 after NGX_OK
input: [1e99999999999999999999]
  exit=134
seed 2:
INVARIANT: stack 1 after NGX_OK
input: [1e99999999999999999999]
  exit=134
seed 3:
INVARIANT: stack 1 after NGX_OK
input: [1e99999999999999999999]
  exit=134
seed 4:
INVARIANT: stack 1 after NGX_OK
input: [1e99999999999999999999]
  exit=134
seed 5:
INVARIANT: stack 1 after NGX_OK
input: [null]
  exit=134
```

With container/key skips only (`maskmod=4`) both builds complete identically (seed 7, 500k iterations:
`done: ok=544523 declined=455477 error=0` on both).

(d) Differential, container/key skips only (`maskmod=4`), trace mode, 200,000 iterations x 2 parses per seed:

```
seed 1: orig exit=0 patched exit=0 lines=400253 IDENTICAL event streams
done: ok=217720 declined=182280 error=0
seed 2: orig exit=0 patched exit=0 lines=400253 IDENTICAL event streams
done: ok=217657 declined=182343 error=0
seed 3: orig exit=0 patched exit=0 lines=400253 IDENTICAL event streams
done: ok=217944 declined=182056 error=0
```

Sanity check that the trace comparison can see a difference: with `maskmod=8` the unpatched trace aborts after
2 lines and the patched one has 4421 lines; `cmp` reports them different at line 1.

## 3. Part 3: Regression test

`/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/regress.c` (standalone; build with `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/build.sh <srcdir> /tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/regress.c <out>`, link against
`ngx_json_parse.c` + `ngx_json_unescape.c`). 36 fixed inputs, each with a deterministic skip rule (event kind +
token + Nth match; `*`/0 = every match) and an expected delivered-event string (`{ } [ ] K: KE: S: E: N: B: Z`,
`!` = handler returned SKIP). Every case also asserts `rc == NGX_OK` and `ctx.depth == 0`; cases flagged `R`
assert no skip residue in `ctx` (all except the two top-level container-skip-at-EOF cases, whose residue is
pre-existing and deliberately not asserted). Coverage: scalar skips (number / string / escaped string / bool /
null; mid-object, last member, top level, single element, whitespace before `]`, trailing whitespace, nested
last element, nested with siblings, followed by a container sibling, repeated skips, final element of the outer
array after an inner skip), scalar skip on an object member value (ignored), KEY skips (mid, last scalar, last
container, nested, only member, escaped key, array-of-arrays value), container skips (mid, last, member, nested
bodies, top level with and without trailing whitespace), top-level scalars, skip on CLOSE, and a no-skip control.

Against the UNPATCHED parser (exit status 1):

```
FAIL   1  scalar skip, array mid-object (MEM-1 repro)
        input:    {"a":[1,2],"b":3}
        expected: { K:a [ N:1! ] K:b N:3 }
        got:      { K:a [ N:1! K:b N:3 }
        reason:   event sequence differs (rc=0)
FAIL   2  scalar skip, array is last member of object
        input:    {"a":[1,2]}
        expected: { K:a [ N:1! ] }
        got:      { K:a [ N:1! }
        reason:   event sequence differs (rc=0)
FAIL   3  scalar skip, top-level array, end of input
        input:    [1,2]
        expected: [ N:1! ]
        got:      [ N:1!
        reason:   event sequence differs (rc=0)
FAIL   4  scalar skip, single element, ']' is next byte
        input:    [1]
        expected: [ N:1! ]
        got:      [ N:1!
        reason:   event sequence differs (rc=0)
FAIL   5  scalar skip, trailing whitespace after top-level ']'
        input:    [1]  
        expected: [ N:1! ]
        got:      [ N:1!
        reason:   event sequence differs (rc=0)
FAIL   6  scalar skip, whitespace before ']'
        input:    [1 ]
        expected: [ N:1! ]
        got:      [ N:1!
        reason:   event sequence differs (rc=0)
FAIL   7  nested: skipped scalar's array is last element of outer array
        input:    [0,[1,2]]
        expected: [ N:0 [ N:1! ] ]
        got:      [ N:0 [ N:1! ]
        reason:   event sequence differs (rc=0)
FAIL   8  nested: inner array is the only element
        input:    [[1,2]]
        expected: [ [ N:1! ] ]
        got:      [ [ N:1! ]
        reason:   event sequence differs (rc=0)
FAIL   9  nested: skip covers only the innermost array; siblings still delivered
        input:    {"a":[[1],[2]],"b":[3]}
        expected: { K:a [ [ N:1! ] [ N:2 ] ] K:b [ N:3 ] }
        got:      { K:a [ [ N:1! [ N:2 ] ] K:b [ N:3 ] }
        reason:   event sequence differs (rc=0)
FAIL  10  scalar skip followed by a nested container sibling
        input:    [1,{"x":2},3]
        expected: [ N:1! ]
        got:      [ N:1!
        reason:   event sequence differs (rc=0)
FAIL  11  scalar skip, string element
        input:    ["x","y"]
        expected: [ S:x! ]
        got:      [ S:x!
        reason:   event sequence differs (rc=0)
FAIL  12  scalar skip, escaped string element
        input:    ["a\u0041",1]
        expected: [ E:a\u0041! ]
        got:      [ E:a\u0041!
        reason:   event sequence differs (rc=0)
FAIL  13  scalar skip, bool element
        input:    [true,null]
        expected: [ B:true! ]
        got:      [ B:true!
        reason:   event sequence differs (rc=0)
FAIL  14  scalar skip, null element
        input:    [null,1]
        expected: [ Z! ]
        got:      [ Z!
        reason:   event sequence differs (rc=0)
FAIL  15  repeated scalar skips in sibling arrays (flag reuse)
        input:    [[1,2],[3,4]]
        expected: [ [ N:1! ] [ N:3! ] ]
        got:      [ [ N:1! [ N:3! ]
        reason:   event sequence differs (rc=0)
FAIL  16  repeated scalar skips, last one directly in the outer array
        input:    [[1,2],[3,4],5]
        expected: [ [ N:1! ] [ N:3! ] N:5! ]
        got:      [ [ N:1! [ N:3! N:5!
        reason:   event sequence differs (rc=0)
PASS  17  scalar skip on object member value (ignored)
PASS  18  key skip mid-object
PASS  19  key skip, last member, scalar value, then '}'
PASS  20  key skip, last member, container value, then '}'
PASS  21  key skip inside nested object that is last member of outer
PASS  22  key skip on the only member, end of input after '}'
PASS  23  escaped key skip
PASS  24  key skip whose value is an array of arrays
PASS  25  container skip mid-array
PASS  26  container skip, last element of array
PASS  27  container skip, object member, more members follow
PASS  28  container skip, nested arrays inside skipped container
PASS  29  container skip at top level, end of input (residue not asserted)
PASS  30  container skip at top level, trailing whitespace
PASS  31  array container skip at top level, end of input (residue not asserted)
PASS  32  top-level number skip (no container)
PASS  33  top-level string skip, trailing whitespace
PASS  34  top-level bool skip
PASS  35  skip returned on a CLOSE event (ignored)
PASS  36  no skip at all
36 cases, 16 failed
```

Against the PATCHED parser (exit status 0):

```
PASS   1  scalar skip, array mid-object (MEM-1 repro)
PASS   2  scalar skip, array is last member of object
PASS   3  scalar skip, top-level array, end of input
PASS   4  scalar skip, single element, ']' is next byte
PASS   5  scalar skip, trailing whitespace after top-level ']'
PASS   6  scalar skip, whitespace before ']'
PASS   7  nested: skipped scalar's array is last element of outer array
PASS   8  nested: inner array is the only element
PASS   9  nested: skip covers only the innermost array; siblings still delivered
PASS  10  scalar skip followed by a nested container sibling
PASS  11  scalar skip, string element
PASS  12  scalar skip, escaped string element
PASS  13  scalar skip, bool element
PASS  14  scalar skip, null element
PASS  15  repeated scalar skips in sibling arrays (flag reuse)
PASS  16  repeated scalar skips, last one directly in the outer array
PASS  17  scalar skip on object member value (ignored)
PASS  18  key skip mid-object
PASS  19  key skip, last member, scalar value, then '}'
PASS  20  key skip, last member, container value, then '}'
PASS  21  key skip inside nested object that is last member of outer
PASS  22  key skip on the only member, end of input after '}'
PASS  23  escaped key skip
PASS  24  key skip whose value is an array of arrays
PASS  25  container skip mid-array
PASS  26  container skip, last element of array
PASS  27  container skip, object member, more members follow
PASS  28  container skip, nested arrays inside skipped container
PASS  29  container skip at top level, end of input (residue not asserted)
PASS  30  container skip at top level, trailing whitespace
PASS  31  array container skip at top level, end of input (residue not asserted)
PASS  32  top-level number skip (no container)
PASS  33  top-level string skip, trailing whitespace
PASS  34  top-level bool skip
PASS  35  skip returned on a CLOSE event (ignored)
PASS  36  no skip at all
36 cases, 0 failed
```

## 4. Files

- Report: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/GH-MEM-1.md` (this file)
- Patch: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/patches/MEM-1.diff`
- Pristine / patched source copies: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/orig/`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/patched/`
- Tools: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/build.sh`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/trace.c` + `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/variants.sh`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/chunk.c`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/json_harness2.c`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/regress.c`
- Logs: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/variants-orig.txt`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/variants-patched.txt`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/chunk-orig.txt`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/chunk-patched.txt`,
  `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/skip_repro-patched.txt`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/fuzz-*.txt`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/diff-m4.txt`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/trace-*.txt`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/perf.txt`,
  `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/regress-orig.txt`, `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/regress-patched.txt`
- Binaries: `/tmp/claude-0/-home-user-nginx-fork/85e39d55-6b91-5013-b099-1cafd270dd52/scratchpad/audit/gh-mem1/bin/`

## 5. Severity note for the tracker

Unchanged from the parent: Low / Informational. API-contract defect in new code, not reachable through the only
in-tree consumer, no memory-safety consequence even for a consumer that tracks a frame stack the way the HTTP
module does (its pop is guarded by `top != NULL`). Recommended to fix anyway: any future scalar-skip user would
desync on the first skipped array element, and the fix is 16 lines with zero behavioural change for the
existing skip kinds.
