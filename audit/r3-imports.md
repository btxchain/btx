# R3 (Imports) — independent review, BTX 0.34.8

Tree: `/home/administrator/btx-0.34.7-private` @ `573b4aa4` + uncommitted working tree.
Lane scope: import plan/coordinator, Hugging Face, Xet, torrent bridge, local host,
cloud streaming. Read-only review plus one **unregistered** test file.

**Nothing in this lane was compiled or executed.** No CMake edit, no
`helper.cpp` / `rpc` / `hcp_engine` edit, no live Hugging Face traffic. Every
"PROVEN" below is a *source-level* proof (exact file and line); every claim that
requires a binary is **NOT_RUN**.

## 0. Verdict

| Claim | Status |
|---|---|
| HF mock vs live | **PROVEN mock-only**; live NOT_RUN and unauthorized |
| Xet large-file | **NOT_RUN**, and **structurally impossible** as written (whole file in RAM) |
| Torrent piece size != BTX 4 MiB | **PROVEN irrelevant for dense maps**; **PROVEN broken for BEP-47 pad files** |
| Path traversal | **PROVEN blocked** on the write path; two latent holes (below) |
| `torrentd` isolation from wallet | **PROVEN by absence** — no process, no library, no socket, no key access |
| Streaming without full local copy | **REFUTED for imports** (full-file RAM read); **REFUTED for cloud hydration** (peak 2x on disk) |

Lane classification: **REAL with three defects** (R3-1, R3-2, R3-3 below). The
prior self-review line "`btx-torrentd` not live; HF live HTTP not authorized"
(`audit/independent-review-r1-r11.md:15`) is accurate but materially incomplete:
it does not mention that the live import RPC fetches **zero** remote bytes, that
staged bytes are **never re-hashed** before `PUBLISH_READY`, or that a torrent
extent read can silently return short.

## 1. SPEC §11–§12 traceability

**Cannot be traced. NOT_RUN.** No document in this tree carries import
sections numbered 11–12. `docs/modelnet/BTX_0348_JIT_Capability_Development_Spec.md`
§11 is "Runtime adapter ABI and platform delivery" and §12 is "First-class modular
adapters and composition" (runtime, not import).
`doc/modelnet/hcp/02_Hosted_Control_Plane_Implementation_Spec.md` §11–§12 are the
financial state machine and release/bounty workflows. The NETWORK-02 import spec
that lane R3 was pointed at is not in the tree, so section-level requirement
traceability is **unverifiable from this checkout**. The review below is against
the code and against the tree's own prose claims
(`doc/modelnet/rpc.md:779`, `doc/modelnet/first-run.md:420-424`,
`audit/architecture-canonicalization.md:29-30`).

## 2. Hugging Face: mock vs live

**PROVEN mock-only.**

- `HuggingFaceByteSource::Read` fails closed with `"not wired to live network"`
  unless `InjectTestBytes` was called (`src/modelnet/source_huggingface.cpp:42-45`).
  There is no HTTP client, no socket, no curl/libevent use in the module.
- The live RPC never asks for bytes. `ExecuteImport` for `HUGGINGFACE` constructs
  the source, calls `Pin()`, and reports `pin_ok` / `pin_error` only
  (`src/modelnet/helper_network02.cpp:211-217`). `StageFromSource` and
  `MakePlanByteSource` have **no non-test callers** anywhere in `src/`.
  So `executemodelimport` on an HF plan transfers no model bytes at all; it
  validates a locator and creates a staging directory.
- Redirects: `Pin()` refuses when `follow_redirects` is set
  (`source_huggingface.cpp:22-26`). `SourceFollowsRedirects()` is a hard `false`
  (`src/modelnet/source_policy.cpp:17-19`).

Findings:

- **R3-4 (LOW, accessor lies).** `FollowsRedirects()` returns the literal
  `false` even when `m_follow_redirects == true`
  (`src/modelnet/source_huggingface.h:41`). `Pin()` is fail-closed, so this is
  not exploitable, but any JSON built from the accessor cannot show that a plan
  requested redirects.
- **R3-5 (MEDIUM, latent SSRF).** `HuggingFaceLocatorAllowed`
  (`src/modelnet/source_local.cpp:113-135`) is a **textual** blocklist with no
  host allowlist and no post-resolution check. It accepts *any* `http(s)` host —
  `https://evil.example/model` passes with `kind=HUGGINGFACE`. Numeric loopback
  encodings are not covered: `http://2130706433/`, `http://0177.0.0.1/`,
  `https://[0:0:0:0:0:0:0:1]/` all pass, as does any DNS name that resolves to
  RFC1918 (rebinding). Harmless today because no resolver and no client exist;
  it becomes a live SSRF the moment an HTTP fetcher is attached. The gate must
  move to post-`getaddrinfo` address checks before HF live is authorized.
- `InjectTestBytes` is a public method on a production class with no
  `#ifdef`/test-only guard (`source_huggingface.h:43`). Not reachable today
  (no caller outside `src/test`), noted for the live wiring review.

Live HF: **NOT_RUN** by instruction and by policy.

## 3. Xet large-file

**NOT_RUN, and not achievable in the current shape.**

- `XetByteSource` holds every chunk in memory: `XetChunkMap` is
  `std::map<std::string, std::vector<unsigned char>>`
  (`src/modelnet/source_xet.h:21`), populated wholesale by `SetChunkMap`. `Pin()`
  only sums chunk sizes (`source_xet.cpp:25-51`). A "large file" therefore
  requires the entire reconstruction resident in RAM before the first byte can be
  read. There is no chunk fetcher, no CAS client, no eviction. Large-file Xet is
  not merely untested; it cannot be run.
- Reachability: `XetByteSource` is compiled (`src/modelnet/CMakeLists.txt:90`)
  but is referenced **only** by `src/test/modelnet_network02_import_tests.cpp`
  and `src/test/modelnet_network02_remain_tests.cpp`. No RPC, no
  `MakePlanByteSource` branch (`import_coordinator.cpp:278-295` has LOCAL / HF /
  TORRENT / MAGNET only). There is no `XET` value in `ImportSourceKind`
  (`import_plan.h:16-23`). **Xet is unreachable from any operator surface.**
  `doc/modelnet/rpc.md:779` and `first-run.md:420` say "HF/Xet/torrent adapters
  … exist and are unit-tested", which is true; they do not claim reachability.
- Positive: the size accumulator has a correct wrap check
  (`source_xet.cpp:41-44`) and `Read` bounds are `offset > m_size ||
  length > m_size - offset` (`source_xet.cpp:62`), i.e. no overflow.
  Cross-chunk stitching is byte-exact.

Findings:

- **R3-6 (MEDIUM).** No chunk-content verification. Chunk ids are plain map keys;
  nothing hashes a blob against its id, and `m_cas_root` is echoed as
  `SourceIntegrity()` without ever being recomputed over the reconstruction
  (`source_xet.h:43`). "CAS reconstruction is source bytes" is currently an
  assertion by the caller, not a check.
- **R3-7 (MEDIUM).** No locator policy for Xet. `Pin()` never calls
  `HuggingFaceLocatorAllowed`, so `XetByteSource("file:///etc/passwd", "cas")`
  pins successfully. The SSRF gate that HF has is simply absent on this adapter.

## 4. Torrent piece size vs BTX 4 MiB

BTX piece size is `PIECE_SIZE = 4U << 20` (`src/modelnet/types.h:74`).

**Dense maps: PROVEN piece-size independent.** The torrent adapter models no
piece geometry at all — `TorrentFileMap` is `{name, size, padding}`
(`erasure_store.h:49-53`) and `MapTorrentRange` (`erasure_store.cpp:266-291`)
maps a global byte extent to per-file byte slices. A torrent with 1 MiB, 4 MiB or
16 MiB pieces produces identical results; BTX re-pieces the byte stream at its
own 4 MiB boundary in `FileStreamHydration` / `ModelStore`. So no piece-size
mismatch bug exists on the mapping path.

**R3-1 (HIGH) — pad files break the extent contract. PROVEN.**
`MapTorrentRange` *drops* padding ranges from the output
(`erasure_store.cpp:281`, `if (a < b && !f.padding)`), while callers pass
torrent-**global** offsets. The result is a `Read` that returns fewer bytes than
`extent.length` and still returns `true`. The existing suite asserts exactly this
without flagging it: `src/test/modelnet_network02_import_tests.cpp:161-162`
requests 6 bytes at offset 8 over `{a:10, pad:2, b:10}` and asserts the result is
the 4-byte string `"89AB"`. An extent lying entirely inside padding returns
success with zero bytes.

The consequence is silent truncation in staging, because
`ImportCoordinator::StageFromSource` never compares the delivered length to the
declared one — it reads `{0, spec.size_bytes}` and writes whatever came back
(`import_coordinator.cpp:191-215`). A plan whose file map contains a pad entry
inside the requested range stages a short file and reports success. BEP-47 pad
files are standard in modern multi-file torrents, so this is reachable input, not
a contrivance. Test `torrent_padding_silently_short_reads_into_staging` in
`src/test/modelnet_r3_import_tests.cpp` isolates it (unregistered → NOT_RUN).

Fixes worth considering: either zero-fill padding and keep extents dense, or
make padding a mapping error, and in all cases add
`if (bytes.size() != spec.size_bytes) return false;` in `StageFromSource`.

**R3-8 (MEDIUM).** `MapTorrentRange` sums `total` with no overflow check
(`erasure_store.cpp:270-271`). A pad entry near `UINT64_MAX` wraps `total` small.
Downstream behaviour is fail-closed-ish (slices come back empty), but combined
with R3-1 the empty-slice path is reported as success.

**R3-9 (MEDIUM).** The infohash is never verified. `Pin()` checks only that the
infohash string is non-empty and that injected payload sizes equal the
plan-declared sizes (`source_torrent.cpp:127-153`); no SHA-1 v1 piece hash, no
v2 merkle root, no `piece length` handling exists. `SourceIntegrity()` returns
the caller's string verbatim. The header comment "infohash is source integrity"
overstates what the code does: today it is a **label**, and real integrity comes
only later from `ChunkLeaf` / `pieces_root` / SHA-384 in
`FileStreamHydration::FinishLocked` (`file_stream.cpp:411-449`) — a path the
import adapters never reach.

## 5. Path traversal

**PROVEN blocked on the write path.**

- Destination paths go through `IsPortableRelPath`
  (`store.cpp:62-94`): regex `^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`, ≤240 bytes,
  per-component rejection of `.`, `..` and trailing dot, plus Windows reserved
  device names. Backslashes, NUL, absolute paths, drive letters and UNC are all
  outside the character class. Applied at parse time
  (`import_plan.cpp:104-108`), again in `PrepareStaging`
  (`import_coordinator.cpp:131-141`) and again in `StageFromSource`
  (`import_coordinator.cpp:181-186`). The only filesystem write is
  `StagingDir() / dest` under a random UUID directory
  (`import_coordinator.cpp:121-124, 201-203`).
- `ImportRelPathUnsafe` additionally rejects dotfiles, any `/.` component and
  executable-ish suffixes (`import_coordinator.cpp:106-114`), and torrent member
  names are filtered by `TorrentFileNameAllowed` (leading `/`, any `..`) both in
  `MapTorrentRangeSafe` and in `Pin`/`Read`
  (`source_torrent.cpp:32-52, 134, 168`).

Latent holes:

- **R3-10 (LOW).** `ParseImportPlan` validates `destination_path` but not
  `source_path` (`import_plan.cpp:96-108`). `PrepareStaging` catches it with
  `ImportRelPathUnsafe(f.source_path)`, so today the file is skipped rather than
  used — but the plan object itself can carry `../../etc/passwd` into
  `TorrentMapFromPlan` (`import_coordinator.cpp:90-102`), where only
  `TorrentFileNameAllowed` stands between it and any future consumer.
- **R3-11 (LOW).** `TorrentFileNameAllowed` filters only literal `..` and a
  leading `/`. Percent-encoded traversal (`%2e%2e/etc/passwd`) is accepted. Safe
  today solely because torrent member names are map keys, never filesystem
  paths. Any future writer that decodes names inherits a traversal.
- **R3-12 (LOW, local host).** `ModelCatalog::ImportPath` walks a directory with
  `recursive_directory_iterator` and accepts anything `is_regular_file()`
  reports, which follows symlinks to files outside the tree
  (`catalog.cpp:550-561`). A local import directory containing a symlink to, say,
  `wallet.dat` copies the target into the model store under the link's name.
  `LocalFileByteSource` itself has no path policy at all, and `SourceLocatorAllowed`
  only checks that a LOCAL locator is non-empty (`source_policy.cpp:23-29`), so
  `kind=LOCAL` with `locator=/any/absolute/path` is read by whatever uid runs the
  helper. Operator-initiated, but it is an arbitrary-read surface for anyone
  holding helper RPC.
- The pickle sniff is head-only: `LooksLikePickle` checks `0x80` + version byte
  (`qualification.cpp:43-48`) and `LooksLikeExecutable` adds ELF/MZ magic plus a
  suffix list (`qualification.cpp:50-61`). A zip-wrapped torch payload named
  `*.safetensors` is not detected by content. Extension coverage catches the
  common cases (`.pt`, `.pth`, `.pkl`, `.py`, `.so`, `.dll`, `.ipynb`, `.sh`,
  `.cu`, plus `.bin`/`.pickle`/`.exe`/`.sig` in `ImportRelPathUnsafe`).

## 6. `torrentd` isolation from wallet

**PROVEN by absence, at the strongest level available without a binary.**

Exact subprocess / library boundary — **there is none; the torrent adapter is
in-process C++ with no I/O**:

1. **No subprocess.** `find` over the tree returns exactly three torrent-named
   files: `doc/modelnet/libtorrent-parts-bin-audit.md`,
   `src/modelnet/source_torrent.h`, `src/modelnet/source_torrent.cpp`. No
   `btx-torrentd` binary, no `contrib/` launcher, no `.service` unit, no
   packaging entry. The only `posix_spawn`/`fork`/`popen`/`std::system` sites in
   `src/modelnet` are the helper supervisor (`supervisor.cpp:326`, spawns
   `helper_exe`), the isolated CUDA qualification worker
   (`qualification.cpp:400`), bounty evaluation (`bounty_eval.cpp:125`), the
   OpenSSL probe (`helper.cpp:7786`) and runtime probes
   (`pq1_runtime.cpp:68`, `capability_runtime.cpp:87`). None is torrent-related.
2. **No third-party library.** `libtorrent` appears in no `CMakeLists.txt`, no
   `depends/packages/*.mk`, and not in `vcpkg.json`. `source_torrent.cpp` is
   compiled straight into the modelnet library
   (`src/modelnet/CMakeLists.txt:91`) and includes only
   `byte_source.h`, `erasure_store.h`, `univalue.h`, `<cstddef>`, `<limits>`.
   `doc/modelnet/libtorrent-parts-bin-audit.md` is explicitly study-only.
3. **No network.** `TorrentByteSource` has no socket, no tracker announce, no
   DHT, no magnet resolution beyond string parsing
   (`ParseTorrentInfohash`, `source_torrent.cpp:12-30`). Payload can only enter
   through the in-process `InjectFileBytes`
   (`source_torrent.cpp:114-120`), whose sole callers are tests.
4. **No credentials, no wallet.** `ReverseTorrentBridge` is two saturating
   `uint64_t` counters plus constant flags: `TorrentdProcess()`,
   `ReceivesS3Credentials()`, `HoldsS3Secrets()` are hardcoded `false`
   (`source_torrent.h:81-83`), `TorrentWorkerReceivesS3Credentials()` is `false`
   (`source_policy.cpp:11-14`). The class has no wallet, key, signing or store
   handle of any kind. `reverse_bridge_live` is true only when the accounting
   object exists, and `ReverseTorrentStatusJson(nullptr)` reports
   `reverse_bridge_live=false` (`source_torrent.cpp:99-105`).
   `gettorrentsourcestatus` / `settorrentsourcepolicy` surface those flags and
   `automatic_spend_atoms=0` (`helper_network02.cpp:763-788, 1005-1017`).

So the wallet-isolation question has a trivially strong answer *because the
bridge does nothing*: it is byte accounting for numbers the RPC caller supplies.
What is **NOT_RUN** is any statement about a real `btx-torrentd`: process
sandboxing, uid separation, credential passing and BitTorrent-wire hardening are
all unevaluated, since no such component exists in this tree.

## 7. Streaming without a full local copy

**REFUTED on the import path.** `StageFromSource` performs a single
`src.Read({0, spec.size_bytes}, bytes, …)` into a `std::vector<unsigned char>`
and then writes the whole vector (`import_coordinator.cpp:191-215`). There is no
chunk loop, no incremental hash, no bounded buffer. A 400 GiB file would require
400 GiB of RAM, and `spec.size_bytes` is caller-supplied plan JSON. The only
brake is `budget_bytes`, also caller-chosen at the call site. Imports are
whole-file-in-RAM by construction.

**REFUTED on the cloud/origin hydration path, for disk.** `FileStreamHydration`
*is* a genuine bounded-memory streamer — 64 KiB read buffer, 4 MiB piece buffer,
per-piece `ChunkLeaf`, resume offsets pinned to `N * PIECE_SIZE`, quarantine
until the file SHA-384 and `pieces_root` match, and only then advertise
(`file_stream.cpp:322-386, 395-461`). But promotion is `CopyPiece`
(`file_stream.cpp:61-67, 451-455`): pieces are copied quarantine → live and the
quarantine copy is never deleted in `FinishLocked`. Peak local footprint is
**2x the file**, and it stays 2x after success unless something outside this file
prunes quarantine. So "no full local copy" is false in both the strong sense (a
full copy is written) and the weak sense (two are).

The only place the tree gets close to "no full local copy" is sparse residency /
verified-slice reads (`capability_bytes.cpp`, `capability_fuse.cpp`
`ReadVerifiedSlice` + `SparseHoleIsUnverified`), which is JIT-lane territory and
is not wired to any import adapter. Cloud layout resolution itself is
policy-only: R2 + AUTO → `SOURCE_FILES` + `STREAM_FILE`, and R2 +
`PIECE_OBJECTS` above 64 projected objects is rejected without
`allow_request_heavy` (`cloud_layout.h:34, 54-67`). Live R2/WAN: **NOT_RUN**.

## 8. Identity: staged bytes are never re-hashed

**R3-2 (HIGH).** `AcceptVerifiedManifest` moves the coordinator to
`PUBLISH_READY` and adopts `vm.model_id` / `vm.artifact_id` after checking only
that the ids are non-null and that `model_id` matches
`expected_btx_manifest` when the plan supplied one
(`import_coordinator.cpp:218-238`). It never hashes the staged files, never
compares them to the plan's sizes, and does not require that any bytes were
staged at all. `StageFromSource` is optional; a coordinator that staged nothing
still reaches `PUBLISH_READY` with a caller-chosen `model_id`. The identity story
in `import_coordinator.h:29-31` ("a final model_id exists only after a
VerifiedManifest is accepted") holds only if the manifest's verifier is
trustworthy and is checked against the same bytes. On the live LOCAL path that
happens to be true — `cat.ImportPath` hashes into the store and
`VerifyManifestAgainstRequest` runs over the resulting manifest
(`helper_network02.cpp:186-205`) — but the coordinator itself provides no such
binding for HF/Xet/torrent, which is precisely where untrusted bytes come from.

**R3-3 (MEDIUM).** `StageFromSource` accepts a short read (see R3-1) and, on
partial write failure, leaves the staging file in place while returning false —
there is no unlink/rollback (`import_coordinator.cpp:203-215`). A subsequent
`AcceptVerifiedManifest` does not notice.

**R3-13 (LOW, latent secret leak).** `ImportPlanJson` serializes
`snapshot_token` (`import_plan.cpp:129`). `ImportCoordinator::StatusJson` is
careful not to (`import_coordinator.cpp:252-276`, asserted by
`modelnet_network02_import_tests.cpp:190-193`), and `ImportPlanJson` has no
non-test caller today. If it is ever wired to an RPC reply or the
`staging.json` marker, the HF token goes with it.

## 9. Evidence status of the new test file

`src/test/modelnet_r3_import_tests.cpp` is written and **not registered in
`src/test/CMakeLists.txt`** (lane rule: do not edit CMake, do not compile).
Its status is therefore **NOT_RUN**. It contains no live network access and no
`/tmp` growth beyond `BasicTestingSetup`'s own datadir. Cases:

| Case | Proves |
|---|---|
| `torrent_dense_map_is_piece_size_agnostic` | byte-exact mapping across file boundaries with no pad entries |
| `torrent_padding_silently_short_reads` | `Read` returns fewer bytes than `extent.length` with `true` (R3-1) |
| `torrent_padding_silently_short_reads_into_staging` | staging writes a 4-byte file for a 6-byte spec and reports success (R3-1/R3-3) |
| `torrent_infohash_is_never_verified` | `Pin` succeeds with an infohash unrelated to the bytes (R3-9) |
| `torrent_traversal_names_rejected` | `..` and leading `/` blocked; `%2e%2e` accepted (R3-11) |
| `torrent_reverse_bridge_holds_no_credentials` | bridge flags and `reverse_bridge_live=false` for `nullptr` (§6) |
| `hf_numeric_loopback_encodings_not_blocked` | `2130706433`, `0177.0.0.1`, `[0:0:...:1]` pin (R3-5) |
| `hf_any_https_host_allowed` | non-HF hosts pass the "HuggingFace" gate (R3-5) |
| `hf_read_requires_injection` | no live HTTP client exists (§2) |
| `xet_locator_has_no_ssrf_gate` | `file:///etc/passwd` pins (R3-7) |
| `xet_chunk_ids_are_not_verified` | content unrelated to its id reconstructs (R3-6) |
| `publish_ready_without_any_staged_bytes` | `PUBLISH_READY` + caller-chosen `model_id` with nothing staged (R3-2) |

Cases marked `_FINDING` in the source assert **current** behaviour that this
review considers wrong; they are documentation of a gap, not an endorsement.

## 10. NOT_RUN ledger for R3

- SPEC §11–§12 section traceability (spec document absent from tree).
- Any compilation or execution, including the new test file.
- Live Hugging Face HTTP, snapshot resolution, redirect behaviour, rate limits.
- Xet CAS fetch, large-file (multi-GiB) reconstruction, chunk dedup.
- `btx-torrentd` as a process: sandbox, uid, credentials, wire protocol, DHT.
- Real BEP-47 torrent with pad files end to end (R3-1 is proven from source and
  from the existing suite's own assertion, not from a live torrent).
- Live R2/WAN cloud streaming; quarantine pruning under disk pressure.
- Wallet-adjacent behaviour of any torrent component (none exists to test).

## 11. Recommended order of fixes

1. R3-1 + R3-3: length check in `StageFromSource`; decide pad semantics in
   `MapTorrentRange` (zero-fill or reject) and fix the existing test that
   asserts the truncation.
2. R3-2: bind `AcceptVerifiedManifest` to the staged bytes — recompute per-file
   SHA-384 / `pieces_root` over `StagingDir()` and compare, and require that
   every accepted file was staged.
3. R3-5 + R3-7: one shared locator gate for every remote adapter, enforced after
   name resolution, with a real host allowlist; apply it to Xet.
4. R3-6 + R3-9: verify chunk ids and torrent piece hashes, or rename the
   accessors so they stop claiming integrity they do not check.
5. Streaming: replace the single full-file `Read` with a bounded loop that feeds
   `FileStreamHydration`, and prune quarantine after promotion.
