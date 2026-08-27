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
`libzmq.a`). See [#111](https://github.com/btxchain/btx/issues/111) and
[#122](https://github.com/btxchain/btx/issues/122) below.

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

## ZMQ on by default (issues 111 and 122)

jarekpiot reported this twice. [#111](https://github.com/btxchain/btx/issues/111)
was the v0.33.3 Linux tarball: `zmqpub*` accepted and ignored,
`getzmqnotifications` absent, no startup failure, a block-explorer
indexer stalled while `btxd` looked healthy. That issue was **closed by
recutting one tarball** with `-DWITH_ZMQ=ON`. CMake's default stayed
OFF. There was no package-time `ldd`/`otool` gate. So the same class of
miss shipped again as [#122](https://github.com/btxchain/btx/issues/122)
in the v0.33.4.2 Linux CPU tarball (`btx-0.33.4.2-linux-x86_64-cpu.tar.gz`,
SHA256 `aecd0725…`, matching our `SHA256SUMS`). CUDA and Metal 0.33.4.2
trees had passed `-DWITH_ZMQ=ON`; the CPU tree had not.

0.34's durable fix, not another one-off recut:

- `option(WITH_ZMQ … ON)` so a forgotten `-DWITH_ZMQ=ON` is no longer
  silent compile-out (`e5cd937a`).
- `find_package(ZeroMQ … REQUIRED)` when the option is on.
- `scripts/release/verify_release_btxd.py` refuses a `btxd` whose help
  text advertises ZMQ without a real libzmq link, and on macOS refuses
  any `/opt/homebrew` load command.
- [release-process.md](release-process.md) makes that `ldd`/`otool`
  check mandatory before a tarball is staged.

Issue 122 stays open until a published 0.34 artifact demonstrates
`getzmqnotifications` and a live `zmqpubhashblock` notification. Do not
treat this notes file as that demonstration.

## SLH-DSA keygen vs libsodium Ed25519

`ecf3ca9f` fixed a **macOS-only silent PQ-to-classical keygen downgrade**
introduced by statically linking `libsodium.a` for ZMQ portability.
SPHINCS+ used the SUPERCOP name `crypto_sign_seed_keypair`; sodium
exports the same name as a 4-byte tail-call into Ed25519. Wallet
`CPQKey::MakeNewKey` → `bitcoin_pqc_keygen` →
`slh_dsa_shake_128s_keygen` called that name and expected a
post-quantum keypair. Linux resolved SPHINCS from `libbitcoinpqc.a`;
macOS kept sodium first. 0.34 prefixes the SPHINCS / `slh_dsa` TUs
(`btx_spx_*`). Dilithium was already `pqcrystals_*`. Reordering the
link to put PQC first would steal ZMQ Curve; do not do that.

**Consensus was never affected.** Mainnet
`GetBlockScriptFlags` sets `SCRIPT_VERIFY_REJECT_LEGACY_SIGS` whenever
`fEnforceP2MROnlyOutputs` is true (it is, from genesis).
`EvalChecksig` then returns `SCRIPT_ERR_BAD_OPCODE` for
BASE / WITNESS_V0 / TAPSCRIPT. PQ signing is
`OP_CHECKSIG_MLDSA` / `OP_CHECKSIG_SLHDSA` under `SigVersion::P2MR`.
libsodium is not a consensus or signing primitive; it arrives
transitively via libzmq for CurveZMQ transport.

If you generated SLH-DSA keys on a macOS `btxd`/`btx-qt` built before
`ecf3ca9f` with static libsodium, treat those keys as **not**
post-quantum and generate new ones on a prefixed binary. Linux
keygen was already SPHINCS. Existing chain signatures were never
Ed25519.

## Trusted-mirror bootstrap deadlock (PR 124)

This is not an operator nicety. Without `1de42d67`, ordinary users on
**new Apple Silicon** get a node that never syncs.

**MendeMatthias** (easyNode / easyBTX) found and reproduced it on
2026-08-26 against v0.33.4.2, and then explained *why* it showed up
for their users at all: easyNode tries `-matmulvalidation=consensus`
on every start and only falls back to a trusted mirror when `btxd`
itself refuses. That refuse happens when Apple silicon self-qualifies
but matches no golden row — today, **M5**. M1 through M4 stay in
consensus mode and never hit the deadlock. The causal chain is:

M5 self-qualifies → no `m5_class` manifest row → `btxd` refuses
consensus → the app falls back to trusted mirror → a **fresh datadir**
hits the bootstrap deadlock and parks at height 0 forever.

Their words: the population this deadlock was hitting is **fresh
installs, not operators**. The M5 golden gap and the bootstrap
deadlock are the same incident, not two unrelated reports. An
`m5_class` row in a fork's own manifest would also remove the fallback
that triggers the deadlock; we will not add that row here (see
[btx-fork-golden-self-sufficiency.md](btx-fork-golden-self-sufficiency.md)).

A fresh `-matmulvalidation=trusted` datadir parked at height 0: archive
peers answered `getheaders` with zero bytes, `NODE_MATMUL_CONSENSUS`
peers offered the only headers and those were dropped as non-authority,
and `MaybeSeedGpuSignedFrontierBestKnown` then pinned BestKnown to the
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
because this tree has no `m5_class` row (MendeMatthias, PR 123). That
refuse is what pushes easyNode/easyBTX onto the trusted-mirror path
and into the bootstrap deadlock above. We will not add the row
ourselves. A fork that ships an installer (including easyNode) adds
`m5_class` to **its** manifest, rebuilds, and reseals; its users then
mine consensus on M5 without waiting on this repository. CUDA `sm_120`
remains the production mining cohort for this line.

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
