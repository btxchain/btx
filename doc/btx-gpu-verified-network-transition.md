# GPU-verified full nodes: three-phase transition

Status: **operator topology for Epoch A**, not a new consensus epoch.
Epochs A–D in [`btx-matmul-v4.7-transition-roadmap.md`](btx-matmul-v4.7-transition-roadmap.md)
decide *what* is consensus authority (ExactReplay, then later a succinct
proof). This document decides *who* must run ExactReplay while Profile 1
ExactReplay is still that authority, without forcing every public seed onto a
GPU before the rest of the stack can carry that cost.

Related:

- [`btx-matmul-trusted-rpc-mirrors.md`](btx-matmul-trusted-rpc-mirrors.md) —
  CPU archive / M-of-N attestation (Phase 1–2)
- [`btx-matmul-v4.7-gpu-operator-runbook.md`](btx-matmul-v4.7-gpu-operator-runbook.md) —
  GPU validator and miner policy
- [`btx-public-node-bootstrap.md`](btx-public-node-bootstrap.md) — public seeds
- [`design/0.34-discovery-relay.md`](design/0.34-discovery-relay.md) — 0.34
  public DNS/addnode hosts are ADDR-only discovery relays, not GPU oracles

## Why this exists

Profile 1 ExactReplay is intentionally expensive. A production validator needs
a qualified GPU. Public headers, IBD, and RPC can run on ordinary VPS hardware
if those machines **do not** ExactReplay and instead follow signed verdicts
from GPU attestors (`-matmulvalidation=trusted` plus `-matmultrustedpubkey`).

That topology is a **stopgap**, not the destination. A trusted mirror is not an
independently validating full node: compromise of `M` attestation keys can make
that operator's mirrors accept false MatMul work. Independent
`-matmulvalidation=consensus` nodes already ignore those signatures as
authority.

The destination is: every node that claims to be a full node ExactReplays on a
GPU. CPU boxes remain light clients, wallets, or explorers. Attestation becomes
optional for machines that cannot replay, not the source of truth for the
public seed layer.

Doing that in one step would mean putting a qualified GPU on every archive
before difficulty, peering, and attestor diversity are in place. The three
phases below keep CPU archives viable until those pieces scale.

This is **GPU-centric full validation**, not “every laptop is a consensus
node.” The hardware floor for a validating full node is a GPU that can
ExactReplay, the same way Bitcoin full nodes need disk and CPU.

## Phase 1 — consensus floor + CPU seeds still follow one attestor

**Goal:** stop easy-ASERT dump inflation and keep public CPU seeds able to
follow the attested chain. Still 1-of-1 GPU attestation.

**Consensus (this release):**

| Item | Value |
|---|---|
| Dump-floor height `nMatMulPowLimitUpgradeHeight` | `191714` |
| Floor compact `powLimitUpgrade` | `0x1f0a3d70` (unchanged) |
| ASERT half-life lengthening | `14400` at height `191715` |
| Profile 1 ExactReplay digest | unchanged (`b4777985…` in the production golden) |
| Golden source slots `[7]`/`[8]` | re-sealed after the logic commit (fingerprint of that tree; not a MatMul change) |

Header `nBits` at and after 191714 cannot be easier than `F`. Independent
miners see that target in `getblocktemplate`. Local extra-work pins
(`-signermintargetcompact`) are **removed** in this release: `F` is
consensus, so GBT `bits`/`target` follow `GetNextWorkRequired`.

**P2P / validation (same binaries, or CPU seeds freeze again):**

- Serve `GETHEADERS` from claimed chain work, or whenever the active tip has a
  configured attestation quorum. Do not use a stale
  `nAuthenticatedChainWork` as the only gate: an ExactReplay-valid attestor
  would otherwise return empty headers and the seed layer would not catch up.
- When ExactReplay or a trusted quorum is recorded, **promote authenticated
  chain work** on that block and its descendants. Recording the bit without
  updating work leaves the serve gate and trust-adjusted ranking on an old
  prefix.
- CPU seeds keep requesting headers from a GPU attestor after the VERSION
  handshake height. A one-shot BestKnown seed at connect time must not stop
  pulls for blocks minted later.
- A GPU attestor ignores unsolicited inbound `BLOCK`/`HEADERS` from
  non-authority peers (same rule trusted mirrors already use). Outbound
  `GETDATA` replies from seeds still count. Random lottery headers must not
  steal ExactReplay from the attestor.
- Caught-up seeds serve historical `GETMMATTEST` from cache. Signer
  regeneration stays limited to archive/mirror catch-up peers and a bounded
  window.

**Roll order:** public CPU archives first, then public miners, **GPU attestor
last**. The first block under the new floor is 191714. A 191714 mined under
the old `nBits` is invalid on the new rule.

**Not in this phase:** extra GPUs, raising `M`, turning archives into GPU
boxes, or dropping `-matmultrustedpubkey` on the seed layer.

## Phase 2 — add GPU attestors (M-of-N), archives stay CPU

**Goal:** remove the single-key / single-feeder failure without buying a GPU
for every seed.

The protocol already supports this:

- Repeat `-matmultrustedpubkey=<hex>` for distinct compressed secp256k1 keys.
- `-matmultrustedthreshold=M` with `1 <= M <= N`.
- Mainnet 1-of-1 starts with a warning: that one key is the node's MatMul
  proof-of-work authority.

How to add a GPU:

1. New attestor: `-matmulvalidation=consensus`, its own key, ExactReplay,
   sign. Prefer it **not** also be the public miner (twin-quorum risk).
2. Every trusted seed (and any node that uses trusted pubkeys) lists every
   attestor key and the same `M`. Compare `replay_authority_context` across
   the fleet before admitting traffic.
3. Seeds `addnode` every attestor so `GETHEADERS` / `GETMMATTEST` are not
   pinned to one host.
4. Public miners keep talking to seeds, not to the GPUs.

Sequence: stay 1-of-1 through Phase 1, add GPU #2 still at `M=1` (availability),
then GPU #3 and **`M=2`**. Adding `N` with `M=1` only creates more machines
that can each freeze or bless a hash alone. Diversifying means `N` grows and
`M` stays a majority (2-of-3, then 3-of-5). Do not use N-of-N: one down box
halts the chain.

Never put ExactReplay or attestor keys on the CPU archives. Never share one
signing key across boxes (that is still 1-of-1).

This is a **federated attestor set**, not “anyone with a GPU is a signer.”
Admission of new keys is an operator process until there is a real key
ceremony.

## Phase 3 — Public seeds become discovery relays; GPU full nodes stay off DNS

**Goal:** the public DNS/`addnode` layer stops being MatMul authority.
Archives follow GPU attestors via the pin. Permissionless miners ExactReplay.
Public introduction hosts only point at other nodes.

Putting a GPU on every public seed would keep those IPs as chain oracles and
keep GETMMATTEST / IBD load on the same machines. That is the opposite of
decentralization.

Convert one public seed at a time: `-matmulvalidation=relay`,
`-disablewallet=1`, drop pin / GETMMATTEST / `NODE_NETWORK`, confirm
`MATMUL_DISCOVERY` is advertised, then the next. Do not flip every public
introduction host in one window. GPU attestors stay `-discover=0` and out
of DNS.

What goes away on those hosts:

- `-matmulvalidation=trusted` (and any pin)
- `NODE_NETWORK` / `NODE_MATMUL_*` authority bits
- `GETMMATTEST` request and serve
- Treating `getbestblockhash` on the seed as the chain

What stays:

- Mining wherever there is hashrate (validation GPU ≠ miner GPU; miners are
  `consensus`, not relays)
- Optional attestations for phones, CPU explorers, and other non-validating
  clients (served by archives, not by relays)
- The Epoch B–D proof roadmap, which is how ExactReplay later becomes an
  audit instead of consensus authority

A CPU VPS that remains a **validating** public node still needs a GPU or
must be honestly named a light client (`trusted` + pin). A CPU VPS that is
only a DNS/addnode pointer runs `relay` and is not a validator.

See [`design/0.34-discovery-relay.md`](design/0.34-discovery-relay.md).

## What this does not change

- **Difficulty** is `nBits` / ASERT / the `F` floor. Extra GPUs do not replace
  the floor.
- **Epochs B–D** (mandatory proof, then proof authority, then Profile 2) remain
  separately reviewed heights. Phase 3 does not skip them.
- **Light clients** never ExactReplay. “Fully decentralized” here means every
  *validating* full node checks MatMul itself.
- **Hashrate** can still concentrate. GPU-centric PoW is not “anyone with a
  VPS is equal.”

## Operator cheat sheet

| Role | Phase 1 | Phase 2 | Phase 3 |
|---|---|---|---|
| Public seed | CPU, `trusted`, follow M-of-N (today 1-of-1) | CPU, `trusted`, follow M-of-N with `M≥2` | GPU, `consensus`, local ExactReplay |
| GPU attestor | 1 key, ExactReplay, sign, ignore inbound lottery | N keys, raise `M` | Optional / light-client attestations only |
| Independent miner | GPU, `consensus`, GBT from seeds | same | same |
| Wallet / explorer | headers / RPC | same | same, or optional attestations |
