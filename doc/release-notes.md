BTX 0.34 is the decentralization release: consensus miners ExactReplay,
public DNS hosts are not chain-tip oracles, and a node with no pin
membership, no attestor key, and no trusted-mirror pin must be able to
reach tip and keep advancing on ExactReplay alone.

`CLIENT_VERSION` in this tree is **0.34.0**. The `v0.34` tag, golden
seal, and the three release tarballs are not this file — they land when
the merge checklist in PR 123 is actually green. Until then Git describe
on `main` remains the 0.33.4.2 line
([release-notes-0.33.4.2.md](release-notes/release-notes-0.33.4.2.md)).

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

Shut down the previous node cleanly, wait for it to exit, and replace
its `btxd`, `btx-cli`, and related binaries with the v0.34 binaries.
Back up wallets and configuration before upgrading. Keep Metal
`.metallib` files next to `btxd`.

Tarball SHA256s are filled in when the three assets are staged (Linux
CPU, Linux CUDA, macOS arm64 Metal). Every shipped `btxd` is linked
with ZMQ (`ldd` shows `libzmq` on Linux; macOS statically links
`libzmq.a`). 0.33.4.2 native tarballs were configured without
`-DWITH_ZMQ=ON` and advertised `-zmqpubhashblock` while publishing
nothing. CMake's default is now ON; release builds still pass
`-DWITH_ZMQ=ON` explicitly. See
[release-process.md](release-process.md).

# Compatibility

Same platform and epoch matrix as 0.33.4.2: Linux, macOS 13+, Windows
10+. Mainnet remains on MatMul v3 below height 185000; Epoch-A Profile 1
ExactReplay applies at and above height 185000. Compact `F`, `powLimit`,
the 191714 `nBits` dump floor, EncDr stall recovery at **199299**
(`num/den = 1/1`), and the compiled AssumeUTXO pin at 199299 are
unchanged.

# Notable Changes

## ExactReplay is the gold standard

`-matmulvalidation=consensus` (the default) accepts and produces
blocks because **this node** ExactReplay'd them. Pin quorum may skip
GPU work and steer FMWC/GBT **only** on trusted CPU archives
(`-matmulvalidation=trusted`). Heard `MMATTEST` never moves BestKnown,
the signed frontier, or GETDATA on a consensus miner.

Public DNS / `addnode` hosts become ADDR-only discovery relays
(`-matmulvalidation=relay`): not MatMul authority, not a chain-tip
oracle, not GETMMATTEST. Independent consensus miners no longer treat
archive GETMMATTEST or a competing pin quorum as a validity or
GPU-admission oracle. Unique unattested tip-children ExactReplay.

The unprivileged-node rule replaces the old operator-fleet gate: a
node holding no pin membership, no attestor key, and no trusted-mirror
pin must reach tip from a cold start on ExactReplay, keep advancing
across a signed-frontier stall without operator action, and recover
without a restart, with every privileged peer absent or hostile.

## Fork self-sufficiency (goldens are a local mining belt)

The production golden manifest is how **this binary** refuses to mine
on a backend it has not measured. It is not a hardware-approval
registry and it is not consensus. Forks that want a new mining backend
add a row to **their** manifest, rebuild, and reseal. Other nodes
ExactReplay the resulting blocks. Do not send golden JSON to this
repository for blessing. See
[btx-fork-golden-self-sufficiency.md](btx-fork-golden-self-sufficiency.md).

## ZMQ on by default

`WITH_ZMQ` defaults to ON. A release `btxd` that contains
`-zmqpubhashblock` strings must actually link libzmq.
`scripts/release/verify_release_btxd.py` checks this.

## Trusted-mirror bootstrap deadlock (PR 124)

Found and reproduced by **MendeMatthias** (easyNode / easyBTX) on
2026-08-26 against v0.33.4.2. A fresh `-matmulvalidation=trusted`
datadir parked at height 0: archive peers answered `getheaders` with
zero bytes, `NODE_MATMUL_CONSENSUS` peers offered the only headers and
those were dropped as non-authority, and
`MaybeSeedGpuSignedFrontierBestKnown` then pinned BestKnown to the
local signed-frontier height (2000) while peers advertised 199300+.
The stall log was:

```text
Seeded GPU peer=7 best-known to signed frontier height=2000 (tip=0 HEADER_ONLY catch-up)
Block fetch stall detected: tip=0 best_header_ahead=2000 peer_best_ahead=2000 in_flight=0
```

`loadtxoutset` cannot rescue that: the snapshot base header must
already be in the index.

0.34 accepts inbound **HEADERS** from any peer while the active tip is
below `max(last checkpoint, highest AssumeUTXO pin)` (mainnet 199299),
and the frontier seed only *raises* BestKnown. Bodies stay
authority-only. You do not need an operator-controlled archive to
learn the header chain. See
[btx-matmul-trusted-rpc-mirrors.md](btx-matmul-trusted-rpc-mirrors.md)
§ Bootstrapping a new mirror.

## Metal is verification-only pending a fork `m5_class` row

`ClassifyMetalDevice` admits mining only on M5-class Metal 4 INT8
TensorOps. M4-class stays verification-only. The historical
`metal-m4` golden was measured on Apple M4 Max; that is our hygiene
for a binary we used to ship, not an ecosystem ruling, and 0.34 does
not reseal it as a production mining backend.

An M5 can self-qualify and still die on `canary=missing_golden`
because this tree has no `m5_class` row (MendeMatthias, PR 123). We
will not add that row ourselves. A fork that wants M5 mining adds it
to its own manifest. CUDA `sm_120` remains the production mining
cohort for this line.

# Fast-start snapshot

Unchanged from 0.33.4.2. Published assumeutxo pin (v9):
[assumeutxo-199299](https://github.com/btxchain/btx/releases/tag/assumeutxo-199299)

- height **199299**, blockhash `f12a27d01a4b5a1710efa4497adf6f4c7da311d1c7b4f6a79cbf80f0b3110ec5`
- `txoutset_hash` `db9e83156602927315d108a1ebce230b30eb78832e69db1947a21f5b5f2b8bf6`
- `snapshot.dat` SHA256 `3c9e52ff053cd183af239dfce42cd57d007bdf530fd48ba9783623662d15070f`

```bash
btx-cli -rpcclienttimeout=0 loadtxoutset snapshot.dat
```

Use `loadtxoutset`, not `loadtxoutsetattested`. Fresh chainstate only.
A 0.34 trusted mirror can now ingest the header chain from public
peers first; 0.33.4.2 could not (see the bootstrap deadlock above).

# Included public work

- btxchain/btx #123 — 0.34 ExactReplay gold standard, discovery relays,
  archive-authority split
- btxchain/btx #124 — trusted-mirror bootstrap deadlock (HEADERS during
  weak-subjectivity sync; seed-raises-only BestKnown). Credit:
  MendeMatthias
- prior `main` line: #105, #112, #113, #117, #119, #120, #121
  (0.33.3–0.33.4.2)

# Consensus

Mainnet EncDr stall recovery remains active at height **199299** with
`num/den = 1/1`. Do not retune `F` or `powLimit` in this release. The
five recovery knobs stay bound into `replay_authority_context`
(schema 4). ExactReplay remains consensus; the canary is not.
