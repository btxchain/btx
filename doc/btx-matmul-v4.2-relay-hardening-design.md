# BTX MatMul v4.2 — Segregated-Proof Relay Hardening Design (Stage 2d)

*Status: DESIGN pass. NOT a consensus-code change, NOT an activation. This document
specifies how to make the segregated-proof RELAY production-ready for the (still
activation-disabled) ENC-BMX4C-D profile, in response to an external audit that found the
Stage-2b relay not production-ready. It builds on
`doc/btx-matmul-v4.2-solver-evolution-design.md` §3 (the segregated-proof mechanism) without
re-deriving it, and on the Stage-2a store / Stage-2b relay already in tree
(`src/matmul/matmul_proof_store.{h,cpp}`, `src/net_processing.cpp`, `src/protocol.h`,
`src/net.{h,cpp}`, `src/pow.cpp`). Nothing here activates D: `nMatMulBMX4CDHeight` stays
`INT32_MAX` on every network; the relay is exercised only under the regtest
`-regtestbmx4cdheight` override. Written 2026-07-17.*

---

## 0. Executive summary

The audit found five defects that keep the segregated-proof relay from being production-ready,
plus a fail-closed posture regression. This design fixes all six as **Stage 2d**, ordered as
one coherent net_processing + params pass (items 1/3/4/6) followed by the production-size test
(item 5). Stage 2c (persistent/pruned/archived storage) lands in parallel; §2 states the
interface contract so 2c and 2d compose.

| # | Defect | Fix (headline) |
|---|---|---|
| 1 | **BIP324 v2 transport truncates the ~32 MiB proof** (24-bit packet-length field caps a v2 packet at ~16 MB; a 32 MiB `matmulproof` overflows → peer disconnect) | Application-layer **chunking**: new `mmproofchunk` message, `MAX_MATMULPROOF_CHUNK_SIZE = 1 MiB`, self-describing chunks, strict bounded reassembly, bind only after full reassembly |
| 2 | Persistent bounded/pruned/archived store (Stage 2c) | Cross-referenced; §2 pins the interface contract + total-bytes cap chunking needs |
| 3 | `m_matmul_proofs_pending` bounds entry COUNT (64) but not BYTES, and entries persist indefinitely | Total **byte budget** (evict lowest-work/oldest, releasing the CBlock + reassembly buffer) + per-entry **expiry** (attempt cap OR node-time TTL) |
| 4 | Tiny `getmatmulproof` → 32 MiB response = ~10⁶× outbound amplification | Per-peer **token bucket** + **global egress budget** + per-(peer,proof) **dedup window** in the responder |
| 5 | Functional test uses n=128 (tiny proof), never exercises v2 at production size | New test: `-regtestmatmulv4dimension=4096` (⇒ m=2048, 32 MiB) over **v2 encrypted** transport, asserting chunk bounds, no v2 disconnect, and rejection of corrupt/oversized/gapped streams |
| 6 | `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY` was flipped **TRUE** while the relay is not production-ready; regtest exemption keys on `fPowNoRetargeting` (which `-test=matmuldgw` clears) | Set flag back to **FALSE** until 1/3/4 + 2c land; re-key the construction-assert exemption on **is_regtest** |

**Chosen values (the numbers to review):**
- **Chunk size** `MAX_MATMULPROOF_CHUNK_SIZE = 1 MiB (1 048 576 B)`; **message** `mmproofchunk(block_hash, chunk_index, total_chunks, total_size, chunk_bytes)`; D ⇒ 32 chunks, C ⇒ 8 chunks; `MAX_MATMULPROOF_CHUNKS` derived from the height's cap, not hardcoded.
- **Pending-queue budget** `MAX_MATMUL_PROOFS_PENDING_BYTES = 128 MiB` (in addition to the 64-entry count cap), evict-lowest-work; **expiry** `MATMUL_PROOF_PENDING_TTL = 20 min` (node clock) OR `MATMUL_PROOF_MAX_ATTEMPTS = 10` fetch cycles.
- **Serving limits** per-peer token bucket (burst 2 proofs, refill 1 / 10 s ≈ 6/min), global egress `MATMUL_PROOF_SERVE_GLOBAL_BYTES_PER_SEC = 8 MiB/s`, dedup window `MATMUL_PROOF_SERVE_DEDUP_WINDOW = 10 min`.
- **Fail-closed**: `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY → false`; assert exemption re-keyed `RELAY_READY || is_regtest`.

---

## 1. BIP324 / v2 transport cannot carry a ~32 MiB proof — application-layer chunking

### 1.1 Root cause (confirmed in tree)

The v2 (BIP324) encrypted transport encodes each packet's content length in a **3-byte
(24-bit) field**: `src/bip324.h:25` `LENGTH_LEN{3}`. The receiver decodes it in
`V2Transport::ProcessReceivedPacketBytes()` (`src/net.cpp:1354-1360`) and rejects anything over

```
MAX_CONTENTS_LEN = 1 + CMessageHeader::MESSAGE_TYPE_SIZE(12) + min(MAX_SIZE, MAX_PROTOCOL_MESSAGE_LENGTH)
                 = 1 + 12 + min(0x02000000 /*32 MiB*/, 16 000 000) = 16 000 013 bytes   (~16 MB)
```

(`src/net.cpp:1350-1352`, `src/net.h:69` `MAX_PROTOCOL_MESSAGE_LENGTH = 16·10⁶`,
`src/serialize.h:33` `MAX_SIZE = 32 MiB`). The 24-bit field itself tops out at 16 777 215.
Either way a v2 packet cannot exceed ~16 MB.

The D proof is `8·m² = 8·2048² = 33 554 432 B = 32 MiB` — **more than double** the v2 ceiling.
The v1-only `MAX_MATMULPROOF_MESSAGE_LENGTH = 40 MB` exception (`src/net.h:96`, applied in
`V1Transport::readHeader` at `src/net.cpp:809-813`) lets a 32 MiB `matmulproof` through on v1,
but v2 cannot key its length gate on the (encrypted) command name, so a single 32 MiB
`matmulproof` over v2 overflows `MAX_CONTENTS_LEN` → `ProcessReceivedPacketBytes` returns false
→ peer disconnect. The existing `src/net.h:90-95` comment already flags this as unsolved. It is
**the** blocker for any real network with v2 peers.

### 1.2 Fix: chunk the proof, reassemble application-side, bind only when whole

Split the proof into fixed-size chunks that fit comfortably under **both** the v2 ~16 MB packet
ceiling and v1's `MAX_PROTOCOL_MESSAGE_LENGTH`, carry each in its own small message, and
reassemble on receipt. Binding + Freivalds run **once, on the fully reassembled blob** — never
per chunk — so the §3.3 soundness cascade is unchanged.

**Chunk size.** `MAX_MATMULPROOF_CHUNK_SIZE = 1 MiB (1 048 576 B)` (new constant in `net.h`).
Justification:
- **~16× under both transport ceilings.** A `mmproofchunk` carrying a 1 MiB payload plus its
  fixed header (32-byte hash + three integers + compactSize framing, < 100 B) is ≈ 1.05 MB —
  far under the v2 `MAX_CONTENTS_LEN` (~16 MB) and the v1 `MAX_PROTOCOL_MESSAGE_LENGTH` (16 MB).
  No transport re-tuning, no v2 24-bit change. A future governance rung (m=4096 ⇒ 128 MiB ⇒ 128
  chunks) still fits with the same message and the same ceilings.
- **Shrinks the DoS envelope** (see §1.6): the per-message unsolicited-buffer cap for this
  command drops from 40 MB to ~1 MiB, a 40× reduction; `MAX_MATMULPROOF_MESSAGE_LENGTH` can be
  retired.
- **Bounded, small reassembly set.** D = 32 chunks, C = 8 chunks — a trivially bounded bitset.
- 2 MiB would also be safe (16 chunks for D); 1 MiB is chosen for finer rate-limit granularity
  (§4) and a smaller per-message allocation.

### 1.3 The chunk message format

One new message replaces the single-shot `matmulproof` response so v1 and v2 share exactly one
code path (always chunk; never emit a monolithic proof). Wire name ≤ 12 bytes:

```
NetMsgType::MATMULPROOFCHUNK = "mmproofchunk"        // src/protocol.h, exactly 12 chars
```

Payload (each chunk is **self-describing** so the receiver can validate/allocate on the first
chunk regardless of arrival order):

| field | type | meaning |
|---|---|---|
| `block_hash`   | `uint256`            | the block the proof binds to (header hash, body-independent) |
| `total_size`   | `uint32_t` (compact) | full proof length in bytes = the profile's exact `8·m²` |
| `total_chunks` | `uint32_t` (compact) | `ceil(total_size / MAX_MATMULPROOF_CHUNK_SIZE)` |
| `chunk_index`  | `uint32_t` (compact) | `[0, total_chunks)` |
| `chunk_bytes`  | `vector<uint8_t>`    | this chunk's slice (1 MiB, except the last = remainder) |

- `getmatmulproof(block_hash)` (`getmmproof`) is unchanged — one request still fetches the whole
  proof; the responder answers with a **sequence of `mmproofchunk` messages** (§4 rate-limits the
  sequence).
- The legacy single-shot `NetMsgType::MATMULPROOF ("mmproof")` handler
  (`src/net_processing.cpp:6027`) is **removed** (or kept as a hard-reject stub for one release);
  all serving goes through chunking. This also lets `MAX_MATMULPROOF_MESSAGE_LENGTH` and the
  `is_matmulproof_msg` branch in `V1Transport::readHeader` (`src/net.cpp:804-813`) be deleted:
  `mmproofchunk` needs no special ceiling.

### 1.4 Strict reassembly (per-peer, single in-flight, bounded)

Reassembly state lives **inside** the existing `QueuedMatMulProof` entry
(`src/net_processing.cpp:1095`), so it is bounded by the same 64-entry / new byte budget (§3)
and there is at most **one** reassembly per held block:

```cpp
struct QueuedMatMulProof {
    std::shared_ptr<const CBlock> block;
    NodeId announced_by{-1};
    NodeId requested_from{-1};            // the ONE peer we accept chunks from
    std::chrono::microseconds requested_time{0us};
    std::set<NodeId> tried_peers;
    // --- Stage 2d reassembly ---
    std::vector<uint8_t> reasm_buf;       // sized to total_size on first valid chunk
    std::vector<bool>    reasm_have;      // total_chunks bits; guards dup/gap
    uint32_t reasm_total_size{0};
    uint32_t reasm_total_chunks{0};
    uint32_t reasm_received{0};           // popcount(reasm_have)
    unsigned attempts{0};                 // §3 expiry
    std::chrono::seconds first_seen{0s};  // §3 TTL (node clock)
};
```

On each `mmproofchunk` from `pfrom` for `block_hash`, in the `MATMULPROOFCHUNK` handler
(new, replacing the `MATMULPROOF` handler at `src/net_processing.cpp:6027`), under `cs_main`:

1. **Solicited-only.** Look up the pending entry; if none, ignore (an unsolicited chunk cannot
   pin memory). If `pfrom != requested_from`, ignore (single in-flight; a peer we didn't ask
   cannot inject chunks).
2. **Cap the declared total BEFORE allocating.** Reject (Misbehaving) if
   `total_size > GetMatMulProofSizeCap(consensus, block_height)` (`src/pow.cpp:3562`, the exact
   `8·m² + 64` cap for the height's profile) — this is the pre-allocation DoS gate.
3. **Consistency.** Reject if `total_chunks != ceil(total_size / MAX_MATMULPROOF_CHUNK_SIZE)`, or
   `total_chunks > MAX_MATMULPROOF_CHUNKS` (derived: `ceil(cap / chunk_size)`), or `chunk_index >=
   total_chunks`. On the first chunk, latch `reasm_total_size/reasm_total_chunks` and allocate
   `reasm_buf(total_size)` + `reasm_have(total_chunks)`. On every later chunk, the declared
   `total_size`/`total_chunks` MUST equal the latched values (a peer cannot resize mid-stream).
4. **Exact per-chunk size (no overlap/gap).** Expected length is
   `MAX_MATMULPROOF_CHUNK_SIZE` for `chunk_index < total_chunks-1`, else `total_size -
   (total_chunks-1)·chunk_size`. Reject on mismatch. Reject **duplicate** (`reasm_have[chunk_index]`
   already set). Copy into `reasm_buf` at `chunk_index·chunk_size`; set the bit; `++reasm_received`.
   Because index and length are exact and duplicates are rejected, the buffer fills with no
   overlap and no gap by construction.
5. **Complete iff `reasm_received == total_chunks`.** Only then move on to binding.

Any rejection in 2–4 marks the peer tried, frees `requested_from`, drops the partial buffer
(so it stops counting against the byte budget), penalizes per severity, and lets SendMessages
re-request from another peer (existing loop, `src/net_processing.cpp:7666`).

### 1.5 Integration with store-put → binding → Freivalds (bind only when whole)

On completion (step 5), the reassembled `reasm_buf` is the candidate proof. Then follow the
**existing** Stage-2b completion path verbatim (`src/net_processing.cpp:6108-6157`):

```
PutMatMulProof(block_hash, std::move(reasm_buf));           // store the untrusted blob
mapBlockSource[block_hash] = {pfrom, /*direct=*/true};      // penalize provider if it fails
ProcessBlock(pfrom, held_block, force=true, min_pow_checked=true);
   → ContextualCheckBlock → CheckMatMulV4SegregatedProof (src/pow.cpp:3568)
        → size cap (again, cheap)                           // MUTATED if over
        → PayloadMatchesCommitment: H(σ‖proof)==matmul_digest (src/pow.cpp:3615)  // MUTATED if not
        → Freivalds VerifySketch* (R=3, ≤2⁻¹⁸⁰)             // CONSENSUS-fail if binds but wrong
```

- A **bad reassembled blob** (any corrupted/substituted chunk that slipped through the size/index
  checks, e.g. wrong *contents*) fails `H(σ‖proof) == matmul_digest` → `MUTATED`, **non-permanent**
  → drop the store bytes + buffer, penalize peer, re-request from another. The honest block is
  never poisoned (mirrors `BLOCK_MUTATED`). This is why binding runs **after full reassembly**:
  the SHA binding is over the whole `8·m²` blob, so it is the end-to-end integrity check the
  per-chunk framing checks deliberately do **not** duplicate.
- A blob that binds yet fails Freivalds / over target is the one permanent `BLOCK_CONSENSUS`
  fault — unchanged from Stage 2b.

**v1 still works.** Chunking is transport-agnostic: v1 peers exchange the same `mmproofchunk`
messages, each well under `MAX_PROTOCOL_MESSAGE_LENGTH`. No v1-specific ceiling is needed anymore,
so the `MAX_MATMULPROOF_MESSAGE_LENGTH` exception is deleted rather than kept. Confirmed against
`V1Transport::readHeader` (`src/net.cpp:759-818`): with the special branch removed, `mmproofchunk`
falls into the default `MAX_PROTOCOL_MESSAGE_LENGTH` limit and passes.

### 1.6 Reconsidering `MAX_MATMULPROOF_MESSAGE_LENGTH` / DoS envelope

Before: the relay needed a 40 MB per-message ceiling (v1-only), a 2.5× widening of the 16 MB
default envelope for that command. After chunking, the largest single proof-relay message is
~1.05 MB, so:
- **Delete** `MAX_MATMULPROOF_MESSAGE_LENGTH` and the `is_matmulproof_msg` branch
  (`src/net.h:96`, `src/net.cpp:804-813`). `mmproofchunk` rides under the 16 MB default on both
  transports.
- The per-message unsolicited-buffer DoS envelope for proof relay drops from **40 MB → ~1 MiB**
  (a peer can force at most one 1 MiB chunk buffer per message before the solicited-only check in
  §1.4 step 1 discards it). Aggregate partial-reassembly memory is separately bounded by the §3
  byte budget.

---

## 2. Interface contract with the persistent store (Stage 2c) — so 1 and 2 compose

Stage 2c implements the design §3.5 storage: an on-disk proof store, the `nMatMulProofPruneDepth`
rolling window (default 10 000 blocks), `-matmulproofarchive` full-retention nodes, IBD re-fetch
above assumevalid, and byte limits. Stage 2d does **not** implement 2c, but the chunking/serving
code depends on a stable store surface. The contract:

1. **Same `Get/Have/Put/Erase` surface** as today (`matmul_proof_store.h:52-64`). The chunking
   responder calls `GetMatMulProof(block_hash, out)` to obtain the full blob to slice into
   chunks; the reassembler calls `PutMatMulProof(block_hash, full_blob)` after completion. 2c may
   back these by disk instead of the in-memory `std::map`, but the signatures and the
   "`Get` returns false = PoW-INCOMPLETE, non-permanent" semantics must not change
   (`matmul_proof_store.h:54-56`).
2. **Store enforces a total-bytes cap.** The store (not net_processing) must bound its own resident
   + on-disk footprint: within the prune window that is ~`8·m² · nMatMulProofPruneDepth` (≈ 32 GiB
   at D per design §3.5). The store MUST expose the byte size of a held proof so the pending-queue
   budget (§3) and serving budget (§4) can account without re-reading the blob. Add
   `size_t ByteSize(block_hash)` / return sizes from `Get`.
3. **Serving pruned/archived proofs.** The §4 responder serves whatever the store holds; archival
   serving of pruned proofs (`-matmulproofarchive`) is a 2c concern, but the responder's rate
   limits (§4) apply identically to archive serving, so 2c inherits them for free.
4. **Chunk-on-serve, not chunk-on-store.** The store holds the flat `8·m²` blob (as today); chunks
   are cut at serve time by the responder. So 2c's on-disk format is unaffected by the choice of
   `MAX_MATMULPROOF_CHUNK_SIZE`, and the chunk size can change in a later release without a store
   migration.

---

## 3. Pending-proof queue — byte budget + expiry

### 3.1 Problem

`m_matmul_proofs_pending` (`src/net_processing.cpp:1109`) is capped at `MAX_MATMUL_PROOFS_PENDING
= 64` **entries**, but each entry holds a full `CBlock` (`std::shared_ptr<const CBlock>`,
`:1097`) and — after §1 — a reassembly buffer up to `8·m²` (32 MiB). 64 × (block + 32 MiB) ≈
**2 GiB** of pinnable memory. Worse, entries have **no expiry**: a block whose proof is
permanently unavailable is held forever (design §3.5 says it must eventually be dropped and
re-requested later via normal sync, never pinned).

### 3.2 Byte budget

Add, alongside the entry-count cap:

```cpp
static constexpr size_t MAX_MATMUL_PROOFS_PENDING_BYTES{128 * 1024 * 1024};  // 128 MiB
```

Track a running `m_matmul_proofs_pending_bytes` = Σ over entries of
`block->GetSerializeSize() + reasm_buf.capacity()`. On insert (or when a first chunk allocates a
reassembly buffer), if the total would exceed the budget, **evict** until it fits:

- **Eviction order:** lowest chain-work first (a block that passed CheckBlock still cost real PoW,
  but a lower-work fork is the cheapest to drop and re-fetch), tie-broken by oldest `first_seen`.
  Never evict an entry that is one completed chunk-set away from binding if a lower-work candidate
  exists.
- **Eviction releases memory:** reset `block` (drop the `shared_ptr`), clear `reasm_buf`/
  `reasm_have`, erase the map entry, decrement the byte counter. `GetLocalMatMulProofStore().Erase`
  is NOT called (the store is a separate cache).
- The evicted block is **re-requestable**: it is dropped from the hold set only; headers-first
  sync will re-announce it and `BlockChecked` (`src/net_processing.cpp:2715`) will re-hold it
  later. Nothing is marked permanently invalid.

128 MiB comfortably holds a handful of concurrent 32 MiB reassemblies plus the small held blocks,
while capping worst-case pinned memory at 1/16 of the naive 2 GiB.

### 3.3 Per-entry expiry (node time source, not wall clock)

Two independent drop conditions, whichever fires first:

```cpp
static constexpr auto   MATMUL_PROOF_PENDING_TTL{20min};   // node-clock wall TTL
static constexpr unsigned MATMUL_PROOF_MAX_ATTEMPTS{10};   // failed fetch cycles
```

- **Attempt cap.** `++entry.attempts` each time a fetch fails (timeout, non-binding proof,
  oversize/gapped chunk stream). At `attempts >= MATMUL_PROOF_MAX_ATTEMPTS`, drop the entry
  (release CBlock + buffer). This subsumes the current `MATMUL_PROOF_RETRY_RESET` long-tail reset
  (`src/net_processing.cpp:125`): after 10 real attempts across the peer set the block is dropped,
  not retried forever.
- **Wall TTL.** `first_seen` is stamped from the **node time source** used everywhere in
  net_processing — `GetTime<std::chrono::seconds>()` / the `current_time` passed into
  SendMessages (`src/net_processing.cpp:439,7666`), which is mockable via `SetMockTime` — **not**
  `std::chrono::system_clock::now()` or any fresh wall-clock read. At
  `current_time - first_seen > MATMUL_PROOF_PENDING_TTL`, drop the entry regardless of attempts
  (covers "every peer is slow/silent"). This is checked in the existing SendMessages sweep
  (`:7667`) and on `mmproofchunk` receipt.

Dropping on expiry releases the held `CBlock` and any reassembly buffer, decrements the byte
counter, and leaves the block re-downloadable via normal sync — exactly the "never pinned forever"
requirement of design §3.5. A block whose proof is genuinely unavailable network-wide simply
falls out of the hold set and is retried the next time it is announced or during a later sync.

---

## 4. `getmatmulproof` serving limits — outbound amplification

### 4.1 Problem

A 32-byte `getmatmulproof` triggers a 32 MiB (chunked) reply — an **~10⁶× amplification**. The
current responder (`src/net_processing.cpp:6001-6024`) serves unconditionally whenever the proof
is held, with no per-peer rate, no global cap, and no dedup. A peer (or a spoofed-source flood)
can spam requests to exhaust the node's uplink.

### 4.2 Three composable limits, hooked in the `GETMATMULPROOF` responder

All three are checked **before** the responder starts emitting `mmproofchunk` messages
(`src/net_processing.cpp:6016`, before `GetMatMulProof`):

1. **Per-peer token bucket** (new per-`Peer` state):
   ```cpp
   static constexpr double  MATMUL_PROOF_SERVE_BUCKET_MAX{2.0};      // burst: 2 proofs
   static constexpr auto    MATMUL_PROOF_SERVE_REFILL{10s};          // +1 proof / 10 s ≈ 6/min
   ```
   Each served proof consumes 1 token; refill is lazy, computed from `current_time` deltas
   (node clock). Empty bucket → **skip serving** (ignore the request, like a `getblocktxn` for a
   block we won't serve — never an error). Sustained per-peer egress is capped at ≈ 6 proofs/min
   ≈ 192 MiB/min/peer at D.
2. **Global egress budget** (single node-wide token bucket on *bytes*):
   ```cpp
   static constexpr size_t MATMUL_PROOF_SERVE_GLOBAL_BYTES_PER_SEC{8 * 1024 * 1024};  // 8 MiB/s
   ```
   Serving a proof reserves `total_size` bytes from the global bucket (charged as chunks are
   emitted). Exhausted → defer/skip this request regardless of peer bucket. Bounds the node's
   total proof-serving uplink independent of peer count, so N peers cannot multiply the drain.
3. **Per-(peer, block) dedup window** (small per-`Peer` LRU of recently-served block hashes):
   ```cpp
   static constexpr auto MATMUL_PROOF_SERVE_DEDUP_WINDOW{10min};
   ```
   Refuse to serve the same proof to the same peer more than once per window (an honest peer that
   got the proof does not need it again in 10 min; re-asking is the amplification pattern).
   Repeated over-limit requests → `Misbehaving` (mild), so a determined spammer is eventually
   disconnected.

These hook cleanly: the responder already ignores requests for proofs it does not hold; the limits
add three more "ignore (optionally penalize)" conditions ahead of the serve. Chunk-level accounting
(1 MiB granularity) lets the global bucket throttle mid-proof if the node is saturated.

---

## 5. Production-size encrypted-transport test (item 5)

### 5.1 Why the current test is insufficient

`test/functional/p2p_matmul_segregated_proof_relay.py` uses `V4_DIMENSION = 128` ⇒ at D's b=2,
m=64 ⇒ proof ≈ 64 KiB — it fits in one v2 packet and **never exercises chunking or the v2 24-bit
limit**. It cannot catch item 1.

### 5.2 Test design: `p2p_matmul_segregated_proof_v2_chunked.py`

**Regtest config.** Activate D at a low height with a **production-scale dimension**:
- `-regtestmatmulv4dimension=4096` ⇒ at D's tile b=2, `m = n/b = 2048` — the production rank, so
  the proof is exactly `8·2048² = 32 MiB`. This is also the mainnet dimension, so it satisfies the
  §4.3 per-profile dimension pin for BOTH C (4096/4=1024) and D (4096/2=2048) in
  `AssertBMX4CConstructionInvariants` (`src/kernel/chainparams.cpp:130-139`).
- `-regtestbmx4cdheight=H_D` (low, e.g. 8), with C at H_C < H_D.
- `-v2transport=1` on both nodes and on the `P2PInterface` (the point of the test: **encrypted**
  transport end-to-end).
- Add `msg_matmulproofchunk` to `test/functional/test_framework/messages.py`.

**Keep CPU tractable.** A real 32 MiB proof requires the full D combine at n=4096; that is the
**smallest** n yielding m=2048 (n=8192 would give m=2048 only at b=4 and costs ~4× the compute for
the same proof, so it is the wrong choice for CI). Even so, one D block's combine is heavy on a CPU
regtest miner. Mitigations: mine **one** D block, cache its proof bytes in the test, and drive all
chunk-stream assertions from that single artifact; the O(n²) Freivalds verify (≈16.7 M mults × 3
rounds) is fast, so the receiver-side cost is dominated by mining, not verification. Give the test
a generous CI timeout and mark it slow/extended.

**Assertions.**
1. **Chunk bounds.** The served stream is exactly `ceil(32 MiB / 1 MiB) = 32` `mmproofchunk`
   messages; each `chunk_bytes` is 1 MiB except the last; every chunk declares
   `total_size == 33 554 432` and `total_chunks == 32`; `chunk_index` covers `[0,32)` once each.
2. **Successful reassembly + no v2 disconnect (the item-1 regression).** The receiver reassembles,
   binds (`H(σ‖proof)==matmul_digest`), Freivalds-verifies, and reaches the **same tip**; assert
   the v2 connection **stays up** across the whole 32-chunk transfer (no BIP324 "packet too large"
   / no disconnect). A control assertion sends the proof as one 32 MiB monolith and expects the v2
   peer to drop — demonstrating the bug the chunking fixes.
3. **Corrupt stream rejected without pinning memory.** Flip one byte in one chunk → reassembled
   blob fails binding → `MUTATED`, block stays proof-INCOMPLETE, tip does **not** move, provider
   penalized; assert the pending byte counter returns to baseline (buffer freed). Then an **honest**
   proof from a second peer completes the block (re-request works).
4. **Oversized / gapped / duplicate rejected pre-reassembly.** (a) a chunk with `chunk_bytes >
   1 MiB` or a declared `total_size > cap` is rejected before allocation; (b) a stream missing an
   index times out and re-requests (no partial credit); (c) a duplicate `chunk_index` is rejected;
   (d) a chunk with inconsistent `total_size`/`total_chunks` vs the first is rejected. In every
   case assert no memory beyond `total_size` is allocated and the tip does not move.

---

## 6. Fail-closed posture (item 6)

### 6.1 (a) Set `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY` back to FALSE

The flag (`src/consensus/params.h:223`) was flipped **true** on the theory that "relay present ⇒
coupling satisfied." Item 1 shows the relay is **not** production-ready (it disconnects v2 peers on
the real proof size), so the coupling the flag asserts — "a node that receives a segregated block
can OBTAIN its proof" (design §3.6) — does **not** hold on any v2 network. Revert:

```cpp
static constexpr bool BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY{false};   // until Stage 2d + 2c land
```

Flip it back to `true` only in the change that lands chunking (§1) + the pending/serving limits
(§3/§4) + the Stage 2c storage. Until then the construction assert
(`src/kernel/chainparams.cpp:214-215`) hard-blocks any **public** network from configuring a D
height, which is the correct fail-closed state. (D is independently inert everywhere via
`nMatMulBMX4CDHeight == INT32_MAX`; this flag is the wire-protocol coupling gate, not the activation
switch, per `src/consensus/params.h:207-222`.)

### 6.2 (b) Re-key the regtest exemption on is_regtest, not `fPowNoRetargeting`

**Bug.** With the flag false, the exemption at `src/kernel/chainparams.cpp:214-215`

```cpp
assert(Consensus::BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY || consensus.fPowNoRetargeting);
```

fails for the matmul regtest tests that run with `-test=matmuldgw`, because that option **clears**
`fPowNoRetargeting` (`src/kernel/chainparams.cpp:1412-1413`). So the very tests that must exercise
the relay (`-regtestbmx4cdheight`) can no longer construct their chain params once the flag is
false — the exemption evaporates exactly when it is needed.

**Fix.** Key the exemption on the **chain being regtest** (the constructor knows its `ChainType`),
not on a retargeting flag a test option mutates. Public networks stay hard-blocked whether or not
they retarget; regtest is always exempt whether or not `-test=matmuldgw` is set.

Exact change:

1. Signature — add an `is_regtest` parameter:
   ```cpp
   // src/kernel/chainparams.cpp:65
   static void AssertBMX4CConstructionInvariants(const Consensus::Params& consensus, bool is_regtest)
   ```
2. Assert — replace `consensus.fPowNoRetargeting` with `is_regtest`:
   ```cpp
   // src/kernel/chainparams.cpp:214-215
   assert(Consensus::BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY || is_regtest);
   ```
   (Update the adjacent comment: the exemption now covers regtest by chain identity, not by the
   `fPowNoRetargeting` proxy, so `-test=matmuldgw` clearing that flag no longer removes it.)
3. Call sites — pass `false` from every public constructor and `true` from regtest:
   - `src/kernel/chainparams.cpp:513` (CMainParams) → `AssertBMX4CConstructionInvariants(consensus, /*is_regtest=*/false)`
   - `:892` (CTestNetParams) → `false`
   - `:1075` (CTestNet4Params) → `false`
   - `:1305` (CSigNetParams) → `false`
   - `:1487` (CRegTestParams) → `true`
   - `:1922` (CShieldedV2DevParams) → `false`

   Equivalently, pass `m_chain_type == ChainType::REGTEST` — all six constructors set `m_chain_type`
   (`:308/:700/:934/:1152/:1318/:1768`) before the assert call. The literal-`true`-at-the-regtest-site
   form is clearer and matches the one call that needs it.

**Net effect:** regtest tests run the relay with the flag **false** (real fail-closed state for
public nets, exercisable in regtest), while every public network — MAIN, TESTNET, TESTNET4, SIGNET,
SHIELDEDV2DEV — stays hard-blocked from setting a D height until the relay is production-ready and
the flag is deliberately re-flipped.

---

## 7. Stage 2d implementation plan (ordering)

One coherent net_processing + params pass (items 1/3/4/6), then the test (item 5). Item 2 is
Stage 2c (parallel); §2 is the contract that lets them merge in either order.

**Pass A — net_processing + protocol + params (items 1, 3, 4, 6):**
1. **Item 6 first (fail-closed):** flip `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY → false`
   (`consensus/params.h:223`) and re-key the assert on `is_regtest` (`kernel/chainparams.cpp`
   §6.2). This restores the safe posture before any relay code moves, and keeps regtest tests
   runnable throughout the rest of the pass.
2. **Item 1 (chunking):** add `NetMsgType::MATMULPROOFCHUNK = "mmproofchunk"` (`protocol.h`) and
   `MAX_MATMULPROOF_CHUNK_SIZE` / derived `MAX_MATMULPROOF_CHUNKS` (`net.h`); delete
   `MAX_MATMULPROOF_MESSAGE_LENGTH` + the `is_matmulproof_msg` branch (`net.h`/`net.cpp`); replace
   the `MATMULPROOF` handler with the `MATMULPROOFCHUNK` reassembler (§1.4) and make the
   `getmatmulproof` responder emit chunks; extend `QueuedMatMulProof` with the reassembly fields
   (§1.4). Bind only on completion (§1.5).
3. **Item 3 (queue budget + expiry):** add `MAX_MATMUL_PROOFS_PENDING_BYTES`, the byte counter +
   evict-lowest-work, and `MATMUL_PROOF_PENDING_TTL` / `MATMUL_PROOF_MAX_ATTEMPTS` using the node
   clock (§3). Reassembly buffers count against the budget, so this must land with item 1.
4. **Item 4 (serving limits):** add the per-peer token bucket, global egress budget, and dedup
   window in the `getmatmulproof` responder (§4).

**Pass B — production-size v2 test (item 5):** `p2p_matmul_segregated_proof_v2_chunked.py` +
`msg_matmulproofchunk` in the test framework (§5). Run under the flag-false / is-regtest-exempt
posture from Pass A step 1.

**Re-flip the flag to true only after** Pass A + Pass B are green AND Stage 2c (persistent
pruned/archived storage, §2) has integrated — that is the single reviewed release action that
makes the relay production-ready. Activating D itself remains a separate, later, measurement-gated
decision (design §6): setting a non-`INT32_MAX` `nMatMulBMX4CDHeight` on a public network is out of
scope for Stage 2d.

---

## 8. Summary of concrete constants

| constant | value | where |
|---|---|---|
| `MAX_MATMULPROOF_CHUNK_SIZE` | 1 MiB (1 048 576 B) | `net.h` (new) |
| `MAX_MATMULPROOF_CHUNKS` | `ceil(GetMatMulProofSizeCap / chunk_size)` (D ⇒ 32) | derived |
| `NetMsgType::MATMULPROOFCHUNK` | `"mmproofchunk"` | `protocol.h` (new) |
| `MAX_MATMULPROOF_MESSAGE_LENGTH` | **deleted** (was 40 MB) | `net.h` / `net.cpp` |
| `MAX_MATMUL_PROOFS_PENDING` | 64 (unchanged, entry count) | `net_processing.cpp:130` |
| `MAX_MATMUL_PROOFS_PENDING_BYTES` | 128 MiB | `net_processing.cpp` (new) |
| `MATMUL_PROOF_PENDING_TTL` | 20 min (node clock) | `net_processing.cpp` (new) |
| `MATMUL_PROOF_MAX_ATTEMPTS` | 10 fetch cycles | `net_processing.cpp` (new) |
| `MATMUL_PROOF_SERVE_BUCKET_MAX` / `_REFILL` | 2 proofs burst / +1 per 10 s | `net_processing.cpp` (new) |
| `MATMUL_PROOF_SERVE_GLOBAL_BYTES_PER_SEC` | 8 MiB/s | `net_processing.cpp` (new) |
| `MATMUL_PROOF_SERVE_DEDUP_WINDOW` | 10 min | `net_processing.cpp` (new) |
| `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY` | **false** (until 2d+2c) | `consensus/params.h:223` |
| construction-assert exemption | `RELAY_READY \|\| is_regtest` | `kernel/chainparams.cpp:214` |
