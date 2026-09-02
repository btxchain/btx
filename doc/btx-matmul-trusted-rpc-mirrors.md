# MatMul v4.7 trusted RPC/archive mirrors

Canonical transition and activation policy:
[`btx-matmul-v4.7-transition-roadmap.md`](btx-matmul-v4.7-transition-roadmap.md).

CPU archives that follow GPU attestors they pin locally are Phases 1–2
of an operator path to GPU-verified validation. Phase 3 drops trusted-mode
on those hosts once they ExactReplay locally. The recommended default is
`-matmulvalidation=consensus` (no pin). See
[`btx-gpu-verified-network-transition.md`](btx-gpu-verified-network-transition.md).

## Purpose and trust boundary

MatMul Profile 1 ExactReplay is intentionally expensive. A deployment that
controls both its validating infrastructure and its RPC fleet may run one or
more qualified GPU archive validators and let cheaper, highly available VPS
machines validate ordinary block contents while trusting signed ExactReplay
verdicts from those archives.

This is an explicit operator-trust topology:

```text
qualified GPU validator(s)
  consensus validation + ExactReplay
  sign (chain, block hash, height, v4, Profile 1, replay authority context)
             |
             | bounded P2P sidecars or RPC export/import
             v
HA trusted mirrors / RPC nodes
  headers + full block bodies + transactions + scripts + state
  M-of-N signature quorum instead of local ExactReplay
```

A trusted mirror is **not an independently validating full node**. Compromise
of at least `M` configured attestation keys can make that operator's mirrors
accept false MatMul work. The signature is not a consensus proof, is not in the
block, does not change the header, and is not Stage-3 proof authority. Nodes in
ordinary `consensus` mode ignore it as validation authority.

## Signed statement and quorum

The domain-separated version-2 statement commits to:

- the genesis hash as chain identifier;
- block header hash;
- exact block height;
- MatMul major version 4; and
- Profile 1; and
- the node's versioned replay-authority context, which fingerprints the
  consensus parameters, activation schedule, and derived episode shapes that
  select the authoritative ExactReplay predicate.

The V2 context is appended after the V1 fields, so the block-hash field keeps
its existing serialized offset. V1 statements and V2 statements produced for
a different replay-authority context are rejected explicitly. This prevents a
valid signature from being replayed after a release or configuration changes
the predicate that an archive claims to have executed, even when chain,
height, and header hash are otherwise unchanged.

Signatures use canonical compressed secp256k1 keys and strict DER/low-S ECDSA.
The store verifies the statement against the local block index and configured
chain before counting it. A signer contributes at most one vote to a block,
and quorum is `M` distinct members of the configured `N` keys. That pin
path is **always sufficient**.

When `-matmulopenattestors=1` (default 0; opt-in directory), additional
GPUs may gossip valid ExactReplay statements with their own keys. Those
statements are **heard**, not authority. After a key co-signs a pin-quorum
hash it is listed as admitted in `getmatmulattestors` so operators can
choose to add it to `-matmultrustedpubkey` (Phase 2). Admitted keys do not
SkipExactReplay and do not move signed-frontier fork choice. Equivocation
freezes an open key in that directory.

ExactReplay skip is a 2×2 of `(trusted_mirror, pin_quorum_covers_hash)`:

| trusted mirror | pin quorum | Skip ExactReplay |
|---|---|---|
| no | no | replay |
| no | yes | replay (consensus never skips because a pin signed) |
| yes | no | replay (unattested hashes still wait/replay) |
| yes | yes | skip (CPU archive; weak subjectivity) |

`HistoricalExactReplayCoveredByPinQuorum(trusted_mirror, direct_quorum,
frontier_covers)` may skip CUDA regen when serving GETMMATTEST: any role
on direct pin quorum, trusted mirrors also on signed-frontier ancestry.
That is a serve budget, not validity; skip never writes
`BLOCK_EXACT_REPLAY_VERIFIED`. FMWC attested steering and getblocktemplate
attested-race refusal apply to trusted mirrors only. Consensus miners mine
the ExactReplay-valid tip. `FindUniqueCompetingAttestedIndex` is
trusted-mirror or local-signer recovery only.

Wrong-chain, wrong-height, wrong-hash, wrong-authority-context, non-member
(when open attestors are off), duplicate, malformed, and invalid signatures
do not count. Relayers have no authority: an attestation can arrive from any
peer because only the signature and local admission rules matter.

Operators should compare `attestation_version` and
`replay_authority_context` from `getmatmultrustedstatus` across every archive
and mirror they chose to follow before admitting traffic. A mismatch is a
configuration/release error and the affected mirror will reject those
attestations.

There is no shipped mainnet attestor pin. README / fast-start /
`gen-btx-node-conf.sh` default to `-matmulvalidation=consensus` with no
keys. Trusted-mirror is an explicit opt-in: the operator supplies
`-matmultrustedpubkey` for attestors they independently trust and can
reach (prefer M≥2). Discover reachable attestors/archives via the
`MATMUL_ATTESTATION_ARCHIVE` / `MATMUL_TRUSTED_MIRROR` service flags.
`getmatmultrustedstatus` and `getfinalityinfo` report *your* pin.
P2P seed connect does not advertise keys. Do not load a signer WIF on
a miner.

## Roles and service capabilities

- `-matmulvalidation=consensus` performs local authority as before. With a
  signing key and serving enabled, it may advertise
  `NODE_MATMUL_ATTESTATION_ARCHIVE`.
- `-matmulvalidation=trusted` performs the trusted-mirror policy, advertises
  `NODE_MATMUL_TRUSTED_MIRROR`, and never advertises
  `NODE_MATMUL_CONSENSUS`.
- Signing keys and `-matmulattestationserve=1` are rejected at startup on
  every non-`consensus` role. A mirror can relay/import statements but can
  never become an authority from stale local metadata.
- The archive-provider and trusted-consumer bits are deliberately different.
  Both are unauthenticated routing hints; signatures remain mandatory.

Trusted mode is accepted on mainnet only with a valid signer set and threshold,
and only for RC Profile 1. Profile 2 statements cannot be produced or consumed
by this protocol. `economic` and `spv` remain prohibited on mainnet.

**0.34 refuses a single-key (1-of-1 or 1-of-N) mainnet trusted mirror** unless
the operator passes `-allowsinglekeytrustedmirror=1`. Two distinct signers
with `-matmultrustedthreshold=2` is the production floor. Above the Profile-1
activation height the quorum does not accelerate the MatMul proof-of-work
check, it replaces it, so a 1-of-1 mirror would make one key that node's sole
proof-of-work authority: whoever holds or steals it could make the node accept
MatMul-invalid blocks, with no second signer able to disagree. Repeating the
same public key is rejected on every chain, since a repeated key raises N
without adding an independent authority. Test networks (testnet/signet/regtest)
still permit 1-of-1 for rehearsals and functional tests. Consensus+pin keeps
1-of-1 as telemetry (ExactReplay is unchanged). See
[`design/0.34-operator-safeguards.md`](design/0.34-operator-safeguards.md).

## Example: two GPU archives and three HA RPC mirrors

Two independent archives are the recommended minimum production topology, not
a protocol-enforced mainnet floor. A 1-of-1 mirror is a single point of
proof-of-work authority: whoever holds or steals that key can make that
mirror accept MatMul-invalid blocks with no second signer to disagree.
0.34 refuses that topology on mainnet unless `-allowsinglekeytrustedmirror=1`.

Generate a dedicated online attestation key per archive. Put each WIF on its
own GPU archive in a permission-restricted file. Distribute only the compressed
public keys to the mirrors.

Each GPU archive (with its own key):

```ini
matmulvalidation=consensus
matmulrcexecution=strict-device
matmultrustedpubkey=02...compressed-public-key
matmulattestationsignerkeyfile=/secure/btx/matmul-attestor.wif
matmulattestationserve=1
# Required when this archive must bootstrap mirrors at every RC height:
# generic script assumevalid must not skip the archive's local ExactReplay.
assumevalid=0
prune=0
```

Each VPS RPC mirror:

```ini
matmulvalidation=trusted
matmultrustedpubkey=02...archive-a-public-key
matmultrustedpubkey=02...archive-b-public-key
# Recommended, not required. Both keys must be distinct; a repeated key IS
# refused, because a duplicate silently inflates the signer count.
matmultrustedthreshold=2
matmultrustedwaitms=30000
connect=<gpu-archive-a-address>
connect=<gpu-archive-b-address>
server=1
prune=0
txindex=1
# Optional: independently check buried ordinary scripts during initial sync.
# The MatMul signer quorum is required with or without this setting.
assumevalid=0
```

Use `rpcbind`, `rpcallowip`, firewalling, authentication, and TLS/reverse-proxy
policy appropriate to the deployment. Trusted MatMul mode does not relax RPC
security.

## Production-shape rehearsal

Run a rehearsal only from an exact, clean, reviewed source revision whose
strict-device manifest contains the archive's provider class. Record the four
reviewed binary SHA256 values and write the result outside the source tree. The
runner mines three production Profile-1 blocks and requires a passed,
provider-bound startup canary plus one explicit strict proof mode. When the
archive mines, use `winner-reseal-authority`: the runner requires fresh
candidate, reseal, exact-header authority publication, and local-authority
consumption telemetry. `last_validation.available=false` is expected in that
mode because local acceptance consumes the one-shot winner authority instead
of replaying the just-resealed block again.

On one Apple Silicon Metal archive, use local mode (no SSH or self-tunnel) and
a disposable regtest-only signing key:

```sh
python3 -u contrib/matmul-v4/two-node-trusted-mirror-rehearsal.py \
  --archive-local \
  --archive-btxd /path/to/metal-build/bin/btxd \
  --archive-cli /path/to/metal-build/bin/btx-cli \
  --archive-backend metal \
  --strict-proof-mode winner-reseal-authority \
  --mirror-btxd /path/to/mirror-build/bin/btxd \
  --mirror-cli /path/to/mirror-build/bin/btx-cli \
  --signer-wif-file /secure/local/disposable-regtest-signer.wif \
  --signer-pub-file /secure/local/disposable-regtest-signer.pub \
  --source-revision <exact-40-character-commit> \
  --archive-btxd-sha256 <reviewed-sha256> \
  --archive-cli-sha256 <reviewed-sha256> \
  --mirror-btxd-sha256 <reviewed-sha256> \
  --mirror-cli-sha256 <reviewed-sha256> \
  --archive-startup-timeout 600 --mine-timeout 900 \
  --mirror-sync-timeout 600 \
  --out /private/result/trusted-mirror-production.json
```

For a remote archive, run the same tool on the mirror host without
`--archive-local`, add `--archive-host`, `--archive-user`, and
`--archive-signer-wif-file`. The latter must name a permission-restricted key
already provisioned on the archive. Remote mode rejects `--signer-wif-file` and
never reads or copies the archive WIF through the mirror host. Only the public
key file belongs on the mirror host. The result contains public provider and
architecture classes, source identity, binary hashes, and counters; it never
contains deployment hostnames, usernames, paths, or private keys.

The checked-in 2026-08-01 two-node artifact is historical toy-dimension
coverage. It is not production closure evidence and must not be relabeled as
such. Generate production evidence only after source, activation parameters,
and final binaries are frozen.

For fault tolerance on the compromise floor, deploy three independent
archive signers and configure the mirrors with all three public keys, keeping
`matmultrustedthreshold=2`. The mirrors can connect to all providers; with
2-of-3 one provider being offline no longer stalls the mirrors, and one key
being compromised still does not independently decide a verdict.

## Bootstrapping a new mirror

A fresh `-matmulvalidation=trusted` datadir used to park at height 0. That
was a code deadlock, not an operator-procedure requirement. Found and
reproduced by MendeMatthias (easyNode / easyBTX) on 2026-08-26 against
v0.33.4.2 (`c892f1a7`), with fourteen peers connected:

- Every `NODE_MATMUL_ATTESTATION_ARCHIVE` peer answered `getheaders` with
  **zero** header bytes, including one that also advertised
  `NODE_MATMUL_CONSENSUS`.
- The only peers that served headers advertised `NODE_MATMUL_CONSENSUS`
  and no archive bit (2000-header batches). Those headers were then
  dropped as non-authority.
- `MaybeSeedGpuSignedFrontierBestKnown` assigned
  `state.pindexBestKnownBlock = seed` unconditionally, pinning BestKnown
  to the local signed-frontier height (2000) while connected peers
  advertised 199300+. The node logged this once a minute, indefinitely:

```text
Seeded GPU peer=7 best-known to signed frontier height=2000 (tip=0 HEADER_ONLY catch-up)
Block fetch stall detected: tip=0 best_header_ahead=2000 peer_best_ahead=2000 in_flight=0 peers_downloading=0
```

`loadtxoutset` cannot break that tie. The AssumeUTXO base header
must already be in the index. 0.34.5's compiled pin is 191266
(`de6e3c9d…`); do not use `f12a27d0…` at 199299 (withdrawn 0.34.1
branch, issue 127).

```text
Unable to load UTXO snapshot: The base block header
(<compiled assumeutxo blockhash>)
must appear in the headers chain.
```

0.34 fixes both halves. While the active tip is below
`max(last checkpoint, highest compiled AssumeUTXO pin)` (mainnet
186000 / 191266 → 191266), inbound **HEADERS** are accepted from any
peer. That is how a fresh node learns the header chain when archives
serve nothing. **BLOCK / CMPCTBLOCK / BLOCKTXN stay authority-only** —
header acquisition is not a body-trust decision. The frontier seed
assigns BestKnown only when it *raises* the peer's target; it never
pins a higher advertised height down to the local seed.

You do not need an operator-controlled archive to bootstrap headers.
An archive you control is still the right body source once headers
exist, and the `connect=` example above still applies for that. Public
header supply plus `loadtxoutset` of the compiled 199299 snapshot is
enough to get a mirror onto the attested chain.

If you still see the stall signatures above, you are on a pre-0.34
binary (or the tip is already past the compiled pin and a different
bug is in play).

Switching `-matmulvalidation` between `consensus` and `trusted` does
not by itself change the persisted replay authority context, so it
does not trigger the reindex path described under **Persistence and
key rotation**. That context follows the configured signer set:
measured byte-identical in both modes for the same three keys on
v0.33.4.2. Changing the signer set still does change it.

## Lifecycle

1. The archive runs authoritative local ExactReplay.
2. Only a successful locally persisted ExactReplay status permits signing.
3. Only after a Profile-1 header or full body passes the shared RC
   ticket/rate/pending-work admission—or a body atomically inherits an already
   admitted header job—does a trusted mirror reserve an outstanding sidecar
   slot and request attestations from archive providers.
4. The validation worker waits up to `-matmultrustedwaitms`.
5. On quorum, the process-local replay memo is populated and ordinary
   `ProcessNewBlock` runs body, transaction, state, chain, and normal script
   validation. As with an ordinary node, the generic buried-script
   `assumevalid` policy is separate; use `-assumevalid=0` to disable it.
6. Authenticated chainwork is assigned only after both quorum and complete-body
   validation succeed.
7. Timeout, cancellation, missing quorum, or local processing failure leaves
   the block retryable. It does not mark it invalid, cache a negative verdict,
   or punish the announcing peer.

Near-tip and historical full-block downloads request the same signed sidecars.
An archive can regenerate a historical attestation after restart only where its
block index durably records its own successful ExactReplay.

The generic buried MatMul recompute shortcut is deliberately disabled in
trusted Profile-1 mode: even historical IBD blocks must present the currently
configured signer quorum. Conversely, a consensus archive that elects to use a
generic assumevalid recompute skip does not set the local ExactReplay bit and
cannot sign that block. Exact and trusted status are written only from explicit
validation provenance, never inferred from a successful contextual check.

## Persistence and key rotation

The mirror's attestation store and replay memo are deliberately process-local.
The block index may retain
`BLOCK_TRUSTED_REPLAY_ATTESTED` for operator audit **and** (on a trusted
mirror only) as the in-process authenticated-chainwork bit for hashes the
current pin covers. Consensus miners never persist that bit; they write
`BLOCK_EXACT_REPLAY_VERIFIED` after local ExactReplay. After restart the
trusted bit is never read as authority. New blocks, and historical blocks that
validation actually revisits, must fetch/import signatures satisfying the
current signer set and threshold.

Already-connected `BLOCK_VALID_SCRIPTS` chainstate is not automatically
replayed merely because the process restarted. Therefore signer/threshold
rotation is prospective by default. To apply a new trust policy retroactively,
the operator must deliberately reindex/revalidate from the chosen height; that
revalidation cannot use the old audit bit as authority. Operators can transfer
a current-policy signed bundle with:

```bash
btx-cli getmatmulattestations <blockhash>
btx-cli submitmatmulattestations '["<serialized-attestation>", ...]'
```

`exportmatmulattestations` and `importmatmulattestations` are aliases for those
commands. `getmatmultrustedstatus` reports role, threshold, retained objects,
quorums, rejects, duplicates, timeouts, and `attested_tip` when a quorum is
known. `getmatmulattestedtip` is the dedicated pool/tooling RPC (height+hash,
whether it sits on the active chain, and whether the active tip itself has
quorum).

## P2P and resource limits

`getmmattest` requests one hash. `mmattest` carries at most 16 attestations and
has a 16 KiB payload cap before vector allocation. The receiver requires a
locally known Profile-1 index entry and independently checks every signature.
Per-peer request and inbound-object token buckets, reconnect-resistant keyed-
netgroup and process-global verification buckets, a bounded outstanding-hash
map, bounded core store, TTL eviction, and bounded unsolicited relay prevent
the sidecar protocol from becoming an allocation or amplification path.
Outstanding requests are inserted only after RC admission, so ticketless false
siblings cannot consume the request map. Store eviction prefers incomplete
buckets and never evicts a completed quorum to admit minority one-vote spam.
When completed quorums fill the configured base capacity, one partial bucket
(at most `threshold - 1` signatures) may be staged beyond it. Only the vote
that completes that bucket may replace the oldest completed quorum, so a
long-running mirror advances without granting minority votes eviction power.

Malformed protocol objects are rejected. A cryptographically invalid
attestation is not evidence that the relaying peer created it, so it is dropped
without treating the referenced block as invalid.

## Operations and recovery

- Monitor `getmatmultrustedstatus`; alert on quorum timeouts, rejected objects,
  missing providers, or a mirror tip lag.
- Run at least two RPC mirrors behind a health-checked load balancer.
- Keep `prune=0` on archive deployments that promise historical block/RPC
  access; enable `txindex=1` on RPC mirrors when transaction-by-id history is
  required. Such a machine is an archive of block/RPC data, not an independent
  MatMul validator.
- Back up the archive's blocks/index and protect the online signing key.
- Pin rehearsals and deployments to reviewed archive/mirror binary SHA256
  values. The rehearsal also requires an exact source revision, derives its
  source-tree fingerprint, and rejects an archive canary whose embedded clean
  build identity differs. A user-supplied revision label alone is not evidence.
- Use M-of-N independent keys for a production fleet. Mainnet does **not**
  enforce a signer floor: a 1-of-1 mirror starts, with a loud startup warning.
  2 distinct signers with `M >= 2` is strongly recommended, and 2-of-3 is
  preferred so one offline provider does not stall the mirrors.
- If a GPU/provider is unhealthy, stop archive attestation service until the
  validator again completes authoritative ExactReplay. Never sign from a
  trusted mirror or from a device failure.
- **Emergency hijack (manual):** `-matmulattestationblocklist=<hex>` at
  start, or `addmatmulattestationblocklist` at runtime, cuts a compromised
  pin or pool key out of attestation authority without a pin re-roll.
  Fail-closed: the node refuses a block that would leave fewer than M
  unblocked pin members. There is no auto-ban from peer counts, heard
  volume, or open-attestor majority (those are Sybil). Runtime adds persist
  across restart; unblocking a persisted key is an operator edit of the
  durable record, not an RPC.
- If mirrors stall, recover or replace an archive signer, reconnect providers,
  or import a bundle. Missing quorum is retryable and source-neutral.
- To regain independent validation, restart a node with
  `-matmulvalidation=consensus` and a qualified strict device, then revalidate
  as required. A trusted mirror status is not transferable into an exact bit.

The production activation gates, complete candidate-plus-reseal timing,
accelerator recovery, admission soak, and ASERT calibration documented by the
v4.7 readiness audit remain separate activation requirements. Trusted mirrors
reduce fleet GPU cost; they do not make the GPU archive's own correctness,
availability, or operational evidence optional.
