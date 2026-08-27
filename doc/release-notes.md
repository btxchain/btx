# STOP: 0.34.1 partitions nodes from mainnet. Do not run it.

**v0.34.1 is an accidental consensus hard fork.** Commit `1c87fcd6`
(PR 119) set `consensus.nMatMulStallRecoveryHeight = 199299` in
`CMainParams` after that height had already been mined. The comment
above that line said any reachable height is a hard fork. 0.34.1
recomputes a different ASERT target for every majority header after
199299, `CalculateClaimedHeadersWork` returns `nullopt`, and
`net_processing.cpp` disconnects the peer. Measured: majority 199299
`a71e0c1c` claims `1e27264f` (plain ASERT); 0.34.1 carries `1e2b22b5`
(re-anchored). About 21 of 94 reachable peers ran 0.34.1 and were
stranded; 73 never left the real chain.

**v0.34.2 withdraws that re-anchor.** `nMatMulStallRecoveryHeight` is
`INT_MAX` again. **Replacing the binary alone does not rejoin.** An
already-split chainstate will not reorg on restart. After installing
0.34.2, operators must also `invalidateblock` their first post-fork
block (reversible with `reconsiderblock`). On the measured 0.34.1
branch that block is height 199295,
`33c834f8056aca85a8591a304fe52affebe2770d6027e79845765547f8dfae82`.
Confirm with `getchaintips` before invalidating.

This split was made visible by per-peer byte tables and chaintips from
**MendeMatthias**, **jarekpiot**, **Jpp-matata**, and **dixonping**.

---

BTX 0.34 is the decentralization release: consensus miners ExactReplay,
public DNS hosts are not chain-tip oracles, and a node with no pin
membership, no attestor key, and no trusted-mirror pin must be able to
reach tip and keep advancing on ExactReplay alone.

`CLIENT_VERSION` in this tree is **0.34.2**. The `v0.34` tag and 0.34.0
seal remain the pool-close cut. 0.34.1 is withdrawn: it partitions
nodes from mainnet. Freeze `F` is recorded in
[0.34.2-freeze.md](evidence/0.34.2-freeze.md); seal and tarballs follow
the corpus. Git describe on `main` remains the 0.33.4.2
line until 0.34 merges
([release-notes-0.33.4.2.md](release-notes/release-notes-0.33.4.2.md)).

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

**If you are on 0.34.1, binary replacement is not enough.** Install
0.34.2, start the node, then invalidate your first post-fork block:

```
btx-cli getchaintips
btx-cli invalidateblock <hash of the first block on your 0.34.1 branch>
```

That `invalidateblock` is reversible with `reconsiderblock`. Do not
invalidate from a still-running 0.34.1 binary: that binary still
rejects the majority chain. Upgrade first, then invalidate.

On the fork measured on macpro2 the first post-fork block is height
199295, hash
`33c834f8056aca85a8591a304fe52affebe2770d6027e79845765547f8dfae82`.
Your hash may differ; use `getchaintips`.

If you never ran 0.34.1 (you stayed on the majority chain), replace
the binaries as usual: shut down cleanly, wait for exit, install
0.34.2. No `invalidateblock` is required.

Keep Metal `.metallib` files next to `btxd`. Back up wallets and
configuration before upgrading.

Tarball SHA256s are filled in when the three assets are staged (Linux
CPU, Linux CUDA, macOS arm64 Metal). Every shipped `btxd` is linked
with ZMQ (`ldd` shows `libzmq` on Linux; macOS statically links
`libzmq.a`). See [#111](https://github.com/btxchain/btx/issues/111) and
[#122](https://github.com/btxchain/btx/issues/122) below.

# Compatibility

Same platform and epoch matrix as 0.33.4.2: Linux, macOS 13+, Windows
10+. Mainnet remains on MatMul v3 below height 185000; Epoch-A Profile 1
ExactReplay applies at and above height 185000. Compact `F`, `powLimit`,
the 191714 `nBits` dump floor, and the compiled AssumeUTXO pin at 199300
are unchanged. **EncDr stall recovery at 199299 is withdrawn** — that
flag day shipped in 0.34.1 after the height was already mined and
partitioned the network. `nMatMulStallRecoveryHeight` is `INT_MAX`;
`num/den` stay `1/1`.

# Notable Changes

## Notice to trusted-mirror operators: repoint or move to consensus

If you run `-matmulvalidation=trusted`, read this before upgrading to
v0.34.1.

**The pin is your choice, not ours.** There is no compiled-in signer key
anywhere in this tree — `grep` `chainparams.cpp` and you will not find one.
Your `-matmultrustedpubkey` entries and your `-matmultrustedthreshold` are
config lines you own. They point at whichever GPU nodes *you* decided to
trust. If that is currently the original operator's keys, it is because those
were the keys that existed, not because the software prefers them.

**We are stepping back.** After v0.34.1 the original operator no longer
commits to running attestation signers. Nodes in `trusted` mode follow a pin;
if the keys you have listed stop signing, your node stops advancing. That is
not a defect, it is what delegated validation means.

**Your options, in order of preference:**

1. **Move to `-matmulvalidation=consensus`.** This is the real fix. A consensus
   node needs no pin, no signers, and no threshold — it accepts a block because
   *this node* ExactReplay'd it. It requires a GPU that passes the byte-exact
   TensorOps self-test. No permission from anyone is involved.
2. **Repoint the pin at signers you actually trust.** Any GPU node running a
   local signing key can attest. Configure two independent ones and keep
   `-matmultrustedthreshold=2`. Mainnet refuses a 1-of-1 quorum for good
   reason: a single stolen key would be sole proof-of-work authority for your
   node.
3. **Revoke specific keys without changing your pin** using
   `-matmulattestationblocklist=<hex>`. Attestations from a blocked key are
   never counted, even if the key is still listed. It is fail-closed: a block
   that would leave you below your own threshold is refused.

**What a trusted mirror is not.** The startup banner says it plainly — a
trusted mirror performs ordinary block, body, and script validation but
delegates the Profile-1 ExactReplay verdict to a configured quorum. It is not
an independently validating full node. That is a reasonable trade for a
CPU-only machine. It should be a deliberate choice, not an inherited default.

Consensus miners and GPU full nodes are unaffected by any of this. They never
consult a pin.

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

## Archives validate independently; relays are the pointers

Public DNS / `addnode` hosts (`node.btx.dev`, `node.btxchain.org`,
`node.btx.tools`) run `-matmulvalidation=relay`: ADDR-only discovery,
not MatMul authority, not a chain-tip oracle. `init.cpp` hard-`InitError`s
if a relay is given a pin, signing key, GETMMATTEST serve, attestation
blocklist, or open attestors.

CPU archives with a full chain run `-matmulvalidation=consensus`. They
ExactReplay independently. They need no pin, no signers, and no
threshold. That is the decentralized outcome: archives are independent
validators, not pin followers.

`MatMulModeIsChainAuthority()` returns true **only** for `CONSENSUS`
and `TRUSTED`. `RELAY` is excluded
(`src/kernel/chainstatemanager_opts.h`). That predicate is the
`chain_oracle` field on `getblockchaininfo` and `getpeerinfo`, so an
operator can verify a discovery relay reports `chain_oracle: false`.

## Validators are optional, not required

A consensus node with **no** `-matmultrustedpubkey` gets an INFO log,
not a warning or error: it cannot see or follow the attested tip, and
`ExactReplay is unchanged`. It validates fully and independently with
zero validator config. That is corroborated three ways: the
gold-standard litmus passes; `SkipExactReplayForGpuAttestation` is
`trusted_mirror && has_valid_gpu_attestation`, so consensus never
skips; and production accepted blocks network-wide while the signer
had attested nothing past 199300.

## Trusted-mirror M=2 is a guard against single-key oracles

`MainnetTrustedMirrorRefusesSingleKey` fires **only** when
`-matmulvalidation=trusted` on mainnet
(`src/node/matmul_trusted_attestations.h`). A consensus node is never
refused. A relay node is never refused. On
`-matmulvalidation=consensus` the pin is telemetry and never skips
ExactReplay. This is the existing mainnet rule, not a 0.34 deadlock
on archives.

It exists because in trusted mode the quorum **replaces** the MatMul
proof-of-work check above the Profile-1 activation height, so a 1-of-1
quorum makes a single WIF that node's sole PoW authority: steal the
key and the node accepts MatMul-invalid blocks. The M=2 floor is a
guard **against** single-key oracles, not a requirement to run a
trusted mirror, and it does not deadlock an archive that validates
with ExactReplay.

Do not pass `-allowsinglekeytrustedmirror=1` to start a public
archive. If a host refuses because it is configured trusted with
threshold 1, switch it to `-matmulvalidation=consensus`. The override
is the single-stolen-key hijack surface this rule removes.

A CPU host with no qualified ExactReplay provider cannot start
`-matmulvalidation=consensus` either. That is a different fail-closed
(`RefuseUnverifiableMatMulConsensusStartup`): Profile-1 needs a
self-qualified accelerator, not a stolen-WIF skip. Do not pass
`-allowunverifiablematmulconsensus=1` on unattended nodes. Public DNS
seeds on CPU run `-matmulvalidation=relay`. A trusted archive still
needs an M-of-N pin, which is not this M=2 startup guard's job to
invent.

The one honest limit: `-matmulvalidation=trusted` nodes still depend
on the pin. The startup warning already says they are **not an
independent full consensus validator**. That is a hardware limit
(CPU-only machines that physically cannot ExactReplay), not a
governance one. After v0.34.1 that pin is yours to keep, repoint, or
leave: see [Notice to trusted-mirror operators](#notice-to-trusted-mirror-operators-repoint-or-move-to-consensus).

## Shielded pool closed at height 199300

At height **199300** (the live tip at this freeze) the shielded pool is
closed in both directions. That is a consensus flag-day
(`nShieldedPoolDisableHeight`), the same idiom as
`nShieldedSmileRiceCodecDisableHeight` /
`nShieldedMatRiCTDisableHeight`. Blocks **below** 199300 validate
exactly as they do today — rewriting history would fail IBD. At and
after 199300:

* shielded **egress** (unshield / spend) is rejected — the remaining
  pool balance (~9,688.79 BTX) is treated as burned, after public
  warning;
* shielded **ingress** (new shielded output) is also rejected, so
  nobody can deposit into a pool they can never leave.

This release closes the pool immediately rather than at a future
height. Ingress has already been consensus-disabled for tens of
thousands of blocks (`nShieldedPoolCreditDisableHeight` follows
`BTX_SHIELDED_SUNSET_HEIGHT`; `nShieldedDirectSendPublicFlowDisableHeight`
is 128000). Egress over the 960-block window 198341–199301 was
**zero** (`getshieldedstateinfo.velocity_window_egress`). The pool is
inert; 0.34 makes that consensus and drops the dormant-pool attack
surface.

Once egress is disabled, shielded state is no longer needed for
**consensus going forward**. The nullifier set exists to stop
double-spends of shielded notes: if no note can ever be spent, no
nullifier can ever be presented. The commitment tree exists to prove
membership for a spend: no spends, no membership proofs. A dormant
pool is pure attack surface, and shielded counterfeiting is invisible
until exit.

Nodes therefore **stop opening** the three shielded LevelDB stores
(`nullifiers`, `commitments`, `account_registry`) by default once the
active tip is at or past 199300. That is the startup saving: no
rebuild, no wasted disk. Explorers and indexers that still want the
historical view pass `-shieldedstate=1`. The code paths are not
deleted; they still validate history below the flag-day.

A local attestor WIF used to be turned into a pubkey in
`AppInitParameterInteraction`, which runs before `ECC_Start`. That
null-dereferenced `secp256k1_context_sign` (~1.2s kernel SEGV, not
shielded warmup / RPC `-28`). The WIF is now staged and derived in
`FinalizeConfiguration` after ECC exists.

## Fork self-sufficiency (goldens are a local mining belt)

The production golden manifest is how **this binary** refuses to mine
on a backend it has not measured. It is not a hardware-approval
registry and it is not consensus. Forks that want a new mining backend
add a row to **their** manifest, rebuild, and reseal. Other nodes
ExactReplay the resulting blocks. Do not send golden JSON to this
repository for blessing. See
[btx-fork-golden-self-sufficiency.md](btx-fork-golden-self-sufficiency.md).

## Header availability, BestKnown `-1`, and IBD (three fixes, one symptom)

A reporter showed archive `getpeerinfo` rows with `sync_height=-1`,
`common_height=-1`, `sync_lag=-1`, and
`counts_as_synced_outbound=false`, and concluded the node was in IBD
and therefore not broadcasting. The effect is right; the cause is one
step off, and it matters because **three different 0.34 fixes** are
involved.

`nSyncHeight` / `nCommonHeight` are filled from
`pindexBestKnownBlock` / `pindexLastCommonBlock`
(`net_processing.cpp` around the getpeerinfo stats). **`-1` means
BestKnown is null** — `UpdateBlockAvailability` never ran for that
peer because we never accepted a header from it. IBD and those `-1`s
are **parallel symptoms** of headers never being learned, not cause
and effect. `counts_as_synced_outbound=false` follows from the same
null BestKnown.

This class was already measured: `net_processing.cpp` documents
**2026-08-11, 26 of 66 peers at `synced_headers=-1`, 11 advertising
heights above our tip**, and already has a rate-limited `getheaders`
probe when BestKnown is null. 0.34 closes the holes that left that
probe as the only recovery path.

1. **`ShouldIgnoreNonAuthorityInboundHeaders` (`1de42d67`).** A trusted
   mirror was dropping non-authority `HEADERS`, so BestKnown never got
   set. Header acquisition during weak-subjectivity bootstrap is not a
   body-trust decision; `BLOCK` / `CMPCTBLOCK` stay authority-only.
2. **Raise-only BestKnown seeding (`1de42d67`).**
   `MaybeSeedGpuSignedFrontierBestKnown` used to overwrite a peer's
   real BestKnown with the lower local signed frontier, pinning
   `peer_best_ahead == best_header_ahead` with `in_flight=0`. Seeding
   may only fill a null or raise.
3. **`DEFAULT_MAX_TIP_AGE` 24h → `30 * 24h` (IBD-LIVE-01).** A node
   whose validated tip is canonical but older than a day used to
   re-enter IBD after every restart. Production confirmed it the same
   day: a GPU signer reported `initialblockdownload=true` on a
   55-hour-old tip at height 199300 while peers were ahead. False IBD
   is not an RPC cosmetic: it suppresses tx announcement, Dandelion,
   and self-advertisement; it also disarms the cadence hold, exempts
   the unauthenticated-header-lead cap, and trips the mining chain
   guard (`after initial_block_download`). Operators who want a
   stricter window still set `-maxtipage`. `btxd -help-debug` reports
   `default: 2592000`. The functional test does **not** mine 30 days in
   the past and does **not** wait on P2P `sync_all` for mocktime-offset
   blocks (that timestamp gap does not converge: node1 receives
   headers and never advances). The compiled default is the help-debug
   string. Stay/leave IBD is exercised with explicit 1- and 2-hour
   `-maxtipage` values by `submitblock` onto the IBD node.

**Raising `maxtipage` alone does not populate `sync_height` /
`common_height`.** That is the header-availability fix (1–2). The
IBD-LIVE-01 audit says the same: increasing `maxtipage` must not be
treated as a substitute for validated header exchange and block-body
request handling. If you deploy expecting the 30-day default to clear
`-1` rows and headers are still dropped for some other reason, the
release did not fail — you are looking at the wrong fix.

Tip age is node policy, not consensus. It becomes a weaker standalone
freshness signal. That is the intended tradeoff under a high-cost
MatMul stall, mitigated by minimum chainwork, validated headers,
authenticated MatMul chainwork, and peer diversity.

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
below `max(last checkpoint, highest AssumeUTXO pin)` (mainnet 199300),
and the frontier seed only *raises* BestKnown. Bodies stay
authority-only. You do not need an operator-controlled archive to
learn the header chain. See
[btx-matmul-trusted-rpc-mirrors.md](btx-matmul-trusted-rpc-mirrors.md)
§ Bootstrapping a new mirror.

## Metal mining is a row you add

Admission is the byte-exact TensorOps self-test
(`IsLtTensorOpsGemmAvailable` / `SelfTestTensorOpsOnce`), not a
device-name string. Mining then requires a golden row for **your**
reported class (`m4_class`, `m5_class`, …). This tree publishes the
classes **we** measured (CUDA `sm_120`). To mine on Metal, add a row
to your copy of
`src/matmul/matmul_v4_rc_production_golden_manifest.data`, rebuild,
and reseal — about four minutes with
[`contrib/matmul-v4/multi-gpu-golden-corpus.sh`](../contrib/matmul-v4/multi-gpu-golden-corpus.sh)
`--backends metal`. Step-by-step:
[btx-fork-golden-self-sufficiency.md](btx-fork-golden-self-sufficiency.md).

easyNode / easyBTX (and any other installer) ships its own `m5_class`
row in **its** freeze. Users get M5 Metal mining without waiting on
this repository. That is the design, not a pending caveat.

## 0.34 is the reference release

Further releases should be **built by the community from this code**,
not requested from us. We are not the gate for goldens, hardware
classes, or future versions. How to freeze, measure, seal, and ship:
[release-process.md](release-process.md) and
[btx-fork-golden-self-sufficiency.md](btx-fork-golden-self-sufficiency.md).

# Fast-start snapshot

Published assumeutxo pin (v9, shielded pool closed):
[assumeutxo-199300](https://github.com/btxchain/btx/releases/tag/assumeutxo-199300)

- height **199300**, blockhash `ff80e6299692a63345674a23b0638658c737529d12e78fc7f42afb3812afc9eb`
- `txoutset_hash` `eb73aed769a9ef5b8f6c9cc4002388e49e4818a1e4cc6cd9d87e107aed5a1352`
- `snapshot.dat` SHA256 `b7ee1459dead9fdb4ed4ee524a6faa66aa0a43ef5280cec00f841289df08e48a`
- `nchaintx` 298984, size 452893894 bytes
- `shielded_state_commitment` `94343b766b39c0ea2d92d83323f77b5ccc5e775d99b34b01f5fa6400f2354541`

```bash
btx-cli -rpcclienttimeout=0 loadtxoutset snapshot.dat
```

Use `loadtxoutset`, not `loadtxoutsetattested`. Fresh chainstate only.
v0.34.0 cannot load this height; v0.34.1 can.
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

Mainnet EncDr stall recovery at height **199299** is **withdrawn**.
0.34.1 set `nMatMulStallRecoveryHeight = 199299` after that height was
already mined; that is a hard fork. 0.34.2 sets it to `INT_MAX` with
`num/den = 1/1`. Do not retune `F` or `powLimit` in this release. The
five recovery knobs stay bound into `replay_authority_context`
(schema 4). ExactReplay remains consensus; the canary is not.
