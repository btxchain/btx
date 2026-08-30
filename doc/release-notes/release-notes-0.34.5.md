BTX 0.34.5 is the sealed follow-up on the `release/0.34.2` line (PR
[#128](https://github.com/btxchain/btx/pull/128)). EncDr ExactReplay digest
is unchanged (`b4777985…`). Compact `F`, `powLimit`, Epoch A (height
185000), and the 191714 dump-floor rule are unchanged.

The shielded pool is closed at height **199300**. The compiled assumeutxo
base is height **201500** (`3dd0fa67…`). The chain is live past **204000**.
Do not load assumeutxo-199299 or assumeutxo-199300 (withdrawn 0.34.1
branch, [issue 127](https://github.com/btxchain/btx/issues/127)).

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

The parent 0.34 notes (0.34.1 partition, 0.34.2 deadlock, 0.34.3/0.34.4
header stalls, Case A/B/C `invalidateblock` traps) remain in
[release-notes.md](../release-notes.md). This file covers the
convergence / self-heal stack that landed on this line.

# How to Upgrade

Shut down the previous node cleanly, wait for it to exit, and replace
its `btxd`, `btx-cli`, and related binaries with the 0.34.5 binaries.
Back up wallets and configuration before upgrading. Keep Metal
`.metallib` files next to `btxd`.

A node that has fallen behind the majority — inherited datadir, frozen
tip, or a parked deep fork — now recovers on that binary upgrade with
**no operator action**, no `invalidateblock`, and no snapshot surgery.
Do not `invalidateblock` `33c834f8` (see Case A in
[release-notes.md](../release-notes.md)).

A datadir that already loaded assumeutxo-199299 or assumeutxo-199300 is
the exception: wipe it and sync from genesis, or load
[assumeutxo-201500](https://github.com/btxchain/btx/releases/tag/assumeutxo-201500)
on a **fresh** chainstate. There is no in-place rescue for those pins.

Tarball SHA256s are filled in when the three assets are staged (Linux
CPU, Linux CUDA, macOS arm64 Metal). Verify `libexec/btxd.real`, not
`bin/btxd`.

# Compatibility

Same platform and epoch matrix as 0.34.4: Linux, macOS 13+, Windows
10+. Mainnet remains on MatMul v3 below height 185000; Epoch-A Profile 1
ExactReplay applies at and above height 185000. EncDr stall recovery at
199299 stays withdrawn (`nMatMulStallRecoveryHeight` is `INT_MAX`).

Default EMERGENCY park depth 6 is unchanged. `-deepforkautoresolve` is
default-on local policy (not a consensus rule). The hidden
`-acquisitionstallseconds` flag is test-only; leave it unset in
production.

# Notable Changes

## Automatic convergence

A consensus node that sits on a minority inherited tip, a frozen
connected tip, or a parked deep majority fork now walks itself onto the
heavier chain after upgrade. The node re-derives majority truth by
re-running GPU-native MatMul PoW locally. It does not follow a peer's
claim, a signed checkpoint, a trusted-quorum shortcut, or a CPU oracle.

Acquisition (fetch + ExactReplay) is separate from migration (unpark +
`ActivateBestChain`). Depth-6 dump-and-run parking stays wired. A
header-only or forged tower fails local re-execution and stays parked.

## Header-sync deadlock (`524c9ecb`)

Header sync had frozen at height **201278** (fork point 199278 + a
full 2000-header batch). Every `getheaders` is anchored at the active
tip, so a peer holding the majority chain answered with a solicited
duplicate batch ending at the local `best_header`, and the node never
asked for the next batch.

Continuation `getheaders` is now anchored at the **batch terminal**,
so header sync always walks forward. The bypass is bounded: the
terminal must advance by a full batch, or a rate-limited retry is
allowed when the terminal sits at `best_header`.

Related, same stack:

- **`4542bcd9`** — never cap header sync below a compiled assumeutxo
  base. A stranded node below height 201500 can always learn the
  snapshot header. The ceiling is `HighestAssumeutxoHeight()` (a fixed
  compiled constant); headers above it keep the anti-flood cap. The
  exemption applies when the tip is acquisition-stale (or IBD); a
  healthy connecting node keeps the full +72 unauthenticated-header
  cap.
- **`18cc8bd6`** ([issue 129](https://github.com/btxchain/btx/issues/129))
  — load the closed-shielded assumeutxo-201500 snapshot section. Past
  the pool close the dumper emits a canonical frozen section (zero
  live counts). The loader now expects that encoding, so
  `loadtxoutset` of assumeutxo-201500 succeeds. Pre-close snapshots
  are unchanged.

## Root-first block download (`7e5fc248`, `72e4d19c`, `2f50a192`)

GPU ExactReplay budget is spent on the **root**: the lowest unverified
body whose parent is already connectable (parent on the active chain,
or itself ExactReplay-verified with data). Driving a high covered body
while the fork-child sat unverified starved the block that actually
connects.

`2f50a192` unshadows that root-first driver on the fetch side and
tolerates lead-overflow so a stall longer than the header-lead window
does not disarm GETDATA of the on-disk frontier.

## RB-16 acquisition escape (`63cc064a` and follow-ups)

Anti-dump caps (`MAX_UNAUTHENTICATED_HEADER_LEAD` 72, last-common snap
at 24) gated *acquisition*, so any node more than 72 blocks behind a
heavier chain could never fetch the competing bodies.

A genuinely stale node (default **600s** with no better-chain
`ConnectTip`; IBD is excluded) may acquire a **strictly-heavier**
competing tower past those caps. Bounds:

- at most **2** concurrent exempt towers (lightest-work eviction)
- exempt header lead **≤ tip+2048**
- migration still park / `-deepforkautoresolve` / quorum gated
- equal-or-lesser work never qualifies

The exempt set is memory-only and cleared on better-chain progress.
Follow-ups make registration restart-safe, admit ExactReplay for
acquired-tower bodies, and evict a slot whose body fails validation.

**`-acquisitionstallseconds`** is a hidden test-only override of the
600s staleness window. It changes only how long a frozen node waits
before the valve may arm — never validation, ExactReplay, or
migration. Do not set it in production.

## `deepforkautoresolve` migration (`a34cf488`, `f4573109`, `7fd6d91c`)

Switching onto an acquired deep fork stays gated. A parked deep
majority fork is un-parked **only** once its entire suffix is locally
ExactReplay-verified: every block `BLOCK_HAVE_DATA` +
`BLOCK_EXACT_REPLAY_VERIFIED`. That bit is set only by
`PersistMatMulExactReplayVerdict` after a local byte-exact
re-execution of the block's MatMul PoW. The trusted-quorum shortcut
sets a different bit and does not satisfy this predicate.

`DeepForkAutoResolveMayUnpark` is strictly harder than
`DeepForkAutoResolveMayAct`. A forged or header-only tower fails
re-execution and stays parked. The depth-6 dump-and-run park is
intact. After unpark, migration is the normal `ActivateBestChain` /
`ConnectTip` path (ExactReplay still required before connect; a
`ConnectBlock` failure marks `BLOCK_FAILED`).

`7fd6d91c` keeps that exact-replay path reachable after restart: a
missing first-seen receive time disqualifies only the live-observation
score, never the suffix-ExactReplay gate. Binary upgrade restarts the
node; bulk-acquired bodies have no live receive stamp.

# Audit posture

Adversarial review of the surrounding path confirmed consensus and
migration gates safe (ExactReplay-before-ConnectTip, park depth 6,
strictly-heavier work, no peer/checkpoint/quorum shortcut). Bounded
hardening from that review is in `f4573109` (forged-tower slot-wedge,
FAILED-parent skip, no synchronous-replay fallback from the retention
store, full-batch continuation bound, sticky `must_probe` budget,
stale-only assumeutxo header-ceiling exemption).

A bounded DoS residual from that review — a solicited-duplicate
header CPU burn, where a peer's repeated all-known 2000-header batches
kept resetting the no-progress disconnect counters — is closed by
`ce11a2aa`: a per-peer terminal high-water counts a solicited replay
batch that does not advance the batch terminal, while legit header-sync
continuation (which always advances) stays exempt. It never affected
validity, park, or migration.

# Fast-start snapshot

[assumeutxo-201500](https://github.com/btxchain/btx/releases/tag/assumeutxo-201500)
(`btx-assumeutxo-201500.dat` SHA256 `08c52c8b34e878c4d48546cfec066bc48fceed51d7287b4ff7ec7b5727cf52c7`)

- height **201500**, blockhash `3dd0fa677029f0b6869b64f09d8673edf3902460767bd6a1ecf6c633b0c6398c`
- `txoutset_hash` `4743962b836a3ed1e541bb6da747fc28a7d98926b5d6bc8e23928ed3b1981d93`
- `nchaintx` 301211
- `shielded_state_commitment` `94343b766b39c0ea2d92d83323f77b5ccc5e775d99b34b01f5fa6400f2354541`
  (same closed-pool pin as 191266)

```bash
btx-cli -rpcclienttimeout=0 loadtxoutset btx-assumeutxo-201500.dat
```

Use `loadtxoutset`, not `loadtxoutsetattested`. Fresh chainstate only.
See [assumeutxo.md](../assumeutxo.md).

# Included public work

- btxchain/btx [#128](https://github.com/btxchain/btx/pull/128) — 0.34.5
  convergence / self-heal stack
- btxchain/btx [#129](https://github.com/btxchain/btx/issues/129) —
  closed-shielded assumeutxo-201500 load (`18cc8bd6`)

# Consensus

No consensus retune in this cut. Epoch A, `F`, `powLimit`, park depth
6, and ExactReplay-before-ConnectTip are unchanged. Migration onto a
deep fork is local policy gated by a local re-execution of the chain's
own PoW.
