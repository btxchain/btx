# R6 Erasure — independent review (SPEC 14)

- Tree: `/home/administrator/btx-0.34.7-private` at `573b4aa4`
- Files reviewed: `src/modelnet/erasure_manifest.{h,cpp}`, `src/modelnet/erasure_store.{h,cpp}`,
  `src/test/modelnet_gap_erasure_tests.cpp`, `src/test/modelnet_erasure_io_tests.cpp`;
  call sites in `src/modelnet/helper_network02.cpp`, `src/rpc/modelnet.cpp`.
- Method: source review only. **Nothing was compiled or executed.** No CMake, helper, or
  production file was edited. New artifact: `src/test/modelnet_r6_erasure_tests.cpp` (not
  registered in the build).

## Verdict

**FAIL for SPEC 14.** The one thing the lane exists to protect — "global shard count does not
imply reconstructability" — is genuinely and correctly implemented, and I want to say so
plainly. But the per-stripe record that replaces the global count is not the record SPEC 14
asks for, and three of its four required fields are absent. Of the four required per-stripe
fields (`k_required`, `independent_shards`, `distinct_failure_domains`, `reconstructable`),
only `reconstructable` is emitted. Worse, the field that actually drives `reconstructable`
is `distinct_effective`, which by construction counts slots that are *not* independent
stored shards.

The prior lane summary in `audit/independent-review-r1-r11.md:18` records R6 as "REAL —
per-stripe unit is real". That is true as far as it goes and I am not overturning the
encode/decode or the anti-global-count work. I am rejecting the claim that the per-stripe
health record is a trustworthy preservation statement.

### The core objection

`ErasureManifestReconstructable` is per stripe. Good. But its input is
`ErasureEffectivePositionSets`, which appends synthetic positions to one stripe:

```198:206:src/modelnet/erasure_manifest.cpp
std::vector<std::vector<int>> ErasureEffectivePositionSets(const ErasureManifest& manifest)
{
    auto sets = ErasureStoredPositionSets(manifest);
    if (sets.empty() || manifest.stripe_count == 0) return sets;
    const auto dummy = LastStripeDummyZeros(manifest);
    if (dummy.empty()) return sets;
    sets.back().insert(sets.back().end(), dummy.begin(), dummy.end());
    return sets;
}
```

`sets.back()` is the stripe that sits last **in the array**, not the stripe with the highest
`stripe_index`. Array order is never validated against index order, and `stripe_index` is
only checked for duplicates (`erasure_manifest.cpp:405-418`), so the author of a manifest
chooses which stripe receives the credit. The size of the credit is
`data_shards - final_real_piece_count`, and `final_real_piece_count` is bounded only by
`1 <= frpc <= k` (`erasure_manifest.cpp:181-184`) — it is never derived from
`file_size_bytes`, `shard_bytes`, and `stripe_count`, none of which are cross-checked
against each other anywhere in the parser.

So: declare `final_real_piece_count: 1` on a 16/20 profile, put the sparse stripe last in
the array, and a stripe holding **one** shard reports `reconstructable: true` and the whole
manifest reports `reconstructable: true`. That is the same class of lie as a global shard
count, relocated one level down. `EvaluateErasureHealth` uses the identical
`i + 1 == manifest.stripes.size()` test (`erasure_manifest.cpp:237-240`), so the health
report agrees with the forged verdict rather than contradicting it.

## Required test matrix

| Case | Status | Where it stands |
| --- | --- | --- |
| k | PASS | Per-stripe, correct. `StripeReconstructable` (`erasure_store.cpp:174-181`) requires k distinct per set. |
| k+N | PASS with a caveat | Surplus is correctly confined to its stripe. `RepairCanonicalFromShards` refuses k+1 inputs outright rather than choosing a k-subset — fail-closed, but it means a caller holding 17 shards cannot repair. |
| k-1 | PASS | A single k-1 stripe defeats any global surplus. Verified by reading; pinned in `r6_a_k_minus_one_survives_a_large_global_surplus`. |
| corrupted shard | **FAIL** | R6-04. No hash is ever checked on the repair path. |
| missing stripe | **FAIL** | R6-05, R6-06. There is no way to name or target one stripe for repair. |
| uneven distribution | PASS | Verdict tracks the worst stripe. |
| all shards in one failure domain | **FAIL** | R6-07. The concept does not exist in the data model. |
| repair restart | **FAIL** | R6-08. `O_EXCL`, no temp file, no rename, no fsync, no verification. |
| codec mismatch | **FAIL** | R6-09. `field_polynomial` is decorative; `profile` has no allowlist. |
| huge logical, bounded memory | **FAIL** | R6-10. Unbounded per-shard read; the I/O bound is sized by the request. |
| old peer ignores extension | **PARTIAL** | R6-11. Forward compat is safe for *data*, unsafe for a future *security* field. |

## Findings

### R6-01 (HIGH) — padding credit forges per-stripe reconstructability

Described above. A one-shard stripe can be declared reconstructable. Fix: credit dummy zeros
only to the stripe whose `stripe_index == stripe_count - 1`, and only after
`final_real_piece_count` has been *derived* from `file_size_bytes` rather than read from the
manifest. Report the credited slots separately from stored shards in the health JSON so an
operator can see that the tail stripe is short by construction.

### R6-02 (HIGH) — manifest geometry is never cross-checked

`stripe_count`, `file_size_bytes`, `shard_bytes` and `final_real_piece_count` are parsed
independently and never reconciled. `stripe_count: 0` with a non-zero `file_size_bytes` is
accepted (it happens to fail closed on the verdict, but it is still an accepted manifest).
`file_size_bytes` may exceed `stripe_count * k * shard_bytes` by any margin. Fix: require
`stripe_count == ceil(file_size_bytes / (k * shard_bytes))` and derive
`final_real_piece_count` from the remainder; reject rather than accept a declared value.

### R6-03 (MEDIUM) — the stripe index set is unconstrained

Indices need only be distinct. A two-stripe manifest may describe stripes 7 and 999, proving
nothing about stripes 0 and 1, and health echoes those indices back
(`erasure_manifest.cpp:266`). Fix: require the index set to be exactly `{0..stripe_count-1}`,
and sort or reject out-of-order arrays. This is also the precondition for fixing R6-01.

### R6-04 (HIGH) — a corrupted shard is decoded into silently wrong canonical data

`ErasureStripe::shard_hash_hex` is parsed, digest-validated, and length-matched against
`positions` (`erasure_manifest.cpp:436-454`) — and then never read again by any code path.
Neither `RepairCanonicalFromShards` nor `RepairStripeFromFiles` hashes anything. A single
flipped bit in one input shard produces k wrong "canonical" data shards, returned as success,
and in the file path written to disk as a completed repair.

`shard_index_root` is in the same position: required, digest-checked, echoed
(`erasure_manifest.cpp:383`, `:292`), bound to nothing. It commits to no shard inventory, so
it cannot detect a substituted or truncated one.

Note that `modelnet_erasure_io_tests.cpp:101` computes a SHA-384 and compares it — but that
is the *test* hashing its own expected output. The production path has no equivalent. This is
exactly the "do not mark PASS from encode/decode unit tests alone" trap: the existing test
proves the codec is correct on honest input and says nothing about dishonest input.

Fix: verify each supplied shard against `shard_hash_hex` before decoding, and verify the
written destination before declaring the repair complete. Bind `shard_index_root` to the set
of stripe/position/hash triples.

### R6-05 (HIGH) — repair never binds to a stripe

```183:187:src/modelnet/erasure_store.cpp
bool RepairCanonicalFromShards(const ErasureManifest& man,
                               const std::vector<std::vector<unsigned char>>& shards,
                               const std::vector<int>& positions,
                               std::vector<std::vector<unsigned char>>& data_out,
                               std::string& err)
```

There is no `stripe_index` parameter. The gate is `ErasureManifestReconstructable(man)`,
which is a statement about *every* stripe, followed by a k-distinct check on the caller's
positions. Nothing requires those positions to be stored by the stripe being repaired, or by
any stripe. In a manifest where stripe 0 stores the even positions and stripe 1 the odd ones,
stripe 1's shards are accepted as a repair with no stripe named at all. The function whose
entire documented purpose is "sufficiency is per stripe" does not know which stripe it is
operating on.

Fix: add a `stripe_index` argument; require every supplied position to appear in that
stripe's stored set; gate on that stripe's own health, not the manifest-wide verdict.

### R6-06 (MEDIUM) — a missing stripe is not addressable

Follows from R6-05. Omitting a stripe's array entry produces the whole-manifest parse error
`"stripes"` (`erasure_manifest.cpp:391-395`), naming nothing. An entry present but with zero
positions is reported with `deficit: 16` but carries no repair handle: the health JSON has no
field telling a healer which positions to fetch or from where. Consequently
`setmodelswarmhealer` cannot execute a repair even in principle, which matches the earlier
lane note at `audit/independent-review-r1-r11.md:18`. The gap is in the data model, not the
healer.

### R6-07 (HIGH) — failure domains do not exist

`ErasureStripe` carries `stripe_index`, `positions`, `shard_hash_hex`. There is no host,
peer, provider, rack, or region field. `ErasureStripeHealth` carries `stripe_index`,
`distinct_stored`, `distinct_effective`, `deficit`, `reconstructable`
(`erasure_manifest.h:47-53`). A grep for `failure_domain` across the tree returns three hits,
all in the matmul/mining adjudication path, none in erasure.

Consequences:

- Sixteen shards on one disk and sixteen shards on sixteen independent hosts produce
  byte-identical manifests and identical health. `reconstructable: true` is therefore not a
  durability statement; it is a statement about arithmetic.
- The `n - k = 4` tolerance the 16/20 profile advertises is unenforceable. Four correlated
  losses is the design margin, and nothing prevents all twenty positions from sharing one
  domain.
- Of the four fields SPEC 14 names, only `reconstructable` is emitted. `k_required` exists
  once globally as `health.k`, not per stripe. `distinct_failure_domains` is absent.
  `independent_shards` is absent, and `distinct_stored` is not a substitute, because the
  verdict is computed from `distinct_effective`, which adds locally-supplyable zeros. The
  number that decides the answer is explicitly not a count of independent shards.

Fix: add a domain identifier per stored position; emit all four fields per stripe; require
`distinct_failure_domains >= n - k + 1` (or a configured tolerance) as a separate gate
alongside the k-distinct gate, and report the two independently so neither can mask the other.

### R6-08 (MEDIUM) — repair restart leaves a permanently poisoned destination

```241:246:src/modelnet/erasure_store.cpp
    const int fd = ::open(dest_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
    if (fd < 0) {
        io.Complete();
        err = (errno == EEXIST) ? "dest exists" : "dest open";
        return false;
    }
```

Writes go straight to the final path. There is no temp file, no atomic rename, and no fsync
before `close` (`erasure_store.cpp:256`). The in-process error path unlinks, but a crash
between `open` and the last `write` leaves a truncated file at `dest_path`. Every subsequent
attempt then returns `"dest exists"` forever, and because of R6-04 nothing ever hashes the
destination, so the partial file is indistinguishable from a completed repair. Restart-only
recovery would be bad; this is worse — restart does not recover at all.

Fix: write to `dest_path + ".tmp.<nonce>"`, fsync, verify the digest, `rename`, fsync the
directory. On restart, verify an existing destination and either accept it or replace it.

### R6-09 (MEDIUM) — codec mismatch is silently accepted

- `field_polynomial` is parsed as a free string (`erasure_manifest.cpp:368-370`) and echoed
  (`:289`). It is compared against `"0x11d"` only when `profile` equals the one reserved
  name. `GfMul` hardcodes `0x11d` (`erasure_store.cpp:123-134`). A manifest declaring
  `0x187` under any other profile name is accepted and decoded with the wrong field, with no
  error and no warning.
- `profile` has no allowlist: any non-empty string up to 64 characters is accepted
  (`erasure_manifest.cpp:327-333`), and outside the reserved name it carries arbitrary
  `data_shards`, `total_shards` and `shard_bytes`.
- Concretely, a `64/80` manifest parses and is evaluated as reconstructable, while
  `getevaluatedtransport` reports `erasure_64_80: NONSHIPPING`
  (`helper_network02.cpp:148`, `helper.cpp:4773`). The honest disposition and the parser
  disagree.

Fix: allowlist `profile`; reject any `field_polynomial` the implementation does not
implement; make the NONSHIPPING dispositions enforced in the parser rather than only reported.

### R6-10 (MEDIUM) — huge logical size is not bounded memory

```219:219:src/modelnet/erasure_store.cpp
    IoExecutor io(std::max<size_t>(1, shard_paths.size() + 1));
```

Two problems. First, the executor's bound is derived from the caller's own request, so it is
never a bound and `IO_EXECUTOR_MAX_OUTSTANDING = 8` is bypassed. Second, each shard is read
with an unbounded `istreambuf_iterator` slurp and only rejected if empty
(`erasure_store.cpp:230-235`). `man.shard_bytes` is known and is never used to cap or check
the read. So:

- An oversized shard file is read whole into RAM; peak usage is O(k × largest file), not
  O(k × shard_bytes).
- A uniformly truncated shard set passes `Linear`'s equal-length check and decodes to
  garbage, because only *mutual* equality is enforced, never equality with `shard_bytes`.
- All files are opened and read before the k-arity check runs inside
  `RepairCanonicalFromShards`, so a 64-path request against a k=2 manifest performs 64 opens
  before being rejected.

Mitigating: `RepairStripeFromFiles` currently has **no production caller**. It is reachable
only from `modelnet_erasure_io_tests.cpp`. The RPC surface (`ErasureFromObject`,
`helper_network02.cpp:568-618`) passes hex shards, not paths. That drops the severity today
but the function is exported in the header as the per-stripe repair I/O entry point, so it
will acquire a caller.

Related asymmetry worth fixing at the same time: `dest_path` is checked for `..` and opened
`O_NOFOLLOW`, while `shard_paths` receive neither check.

### R6-11 (LOW) — forward compatibility has no must-understand mechanism

`version` must be exactly `1` (`erasure_manifest.cpp:322-326`), and unknown keys are silently
ignored. For data-carrying extensions that is correct and safe, and I confirmed that unknown
subtrees are still walked by `RejectFloatsAndSecrets`, so an extension cannot smuggle a float
or a secret-bearing key past the parser (`erasure_manifest.cpp:60-89`, `:320`).

The problem is specific to R6-07. When a future revision adds `stripes[].failure_domain`, an
old peer will ignore it and answer `reconstructable: true` on a manifest a new peer correctly
rejects. There is no `required_extensions` list or must-understand flag, so the older answer
is a silent downgrade rather than a refusal. Fix before shipping the domain field, not after:
add a `required_extensions` array that an unrecognised entry causes a hard parse failure.

### R6-12 (LOW) — the informational global counter is inflatable

`global_position_count` sums `positions.size()` including duplicates
(`erasure_manifest.cpp:236`). Twenty copies of position 3 in one stripe report
`global_position_count: 20` with `distinct_stored: 1`. The verdict is unaffected, and the
JSON does carry `global_count_not_sufficiency: true` (`:261`), which is the right instinct.
But the inflatable number is the one an operator eyeballs. Sum distinct positions instead.

## What is genuinely sound

Recording these so a later lane does not re-litigate them:

- `StripeReconstructable` (`erasure_store.cpp:174-181`) and
  `ErasureManifestReconstructable` (`erasure_manifest.cpp:209-217`) are per stripe and never consult `n` or a
  global count. The thesis is implemented, not just asserted in comments.
- `RepairCanonicalFromShards` gates on the per-stripe verdict before touching the codec and
  returns the explicit error `"global n is not sufficiency"`.
- Duplicate positions are deduplicated via `std::set` before counting, in both the health
  path and the reconstructability path.
- `ErasureHealthJson` labels `global_position_count` as informational and emits
  `global_count_not_sufficiency: true`.
- The parser fails closed on absent or short `stripes`, rejects floats, rejects
  secret-bearing keys (including inside unknown subtrees), bounds nesting at 32, stripes at
  1e6, and positions at 255, and validates every position against `total_shards`.
- The Cauchy generator and GF(256) inverse are correct, and the reserved 16/20 profile name
  does pin its own dimensions.

## Artifact

`src/test/modelnet_r6_erasure_tests.cpp` — **written, not compiled, not registered in
`src/test/CMakeLists.txt`.** Two parts:

- **Part A** (6 cases) pins the sound behaviour above with per-stripe assertions that do not
  exist in the two current test files: the 16/20 profile rather than a 2/4 toy, a nine-stripe
  manifest whose global surplus exceeds the requirement by 31 positions while one stripe sits
  at k-1, duplicate-position dedup, repair arity at k-1/k/k+1 with four parity positions in
  the k case, parser bounds, and secret/float rejection inside an unknown extension.
- **Part B** (8 cases) are deliberate RED assertions, one per finding R6-01 through R6-10.
  Each states the property SPEC 14 requires and fails against `573b4aa4`. Do not register
  this file in `test_btx` until the findings are closed — it will turn the suite red on
  purpose, which is the point.

I did not add it to CMake, did not touch `helper.cpp`, and did not build. Whoever picks this
up should treat Part B as the specification for the fix and Part A as the regression fence
around the parts that already work.
