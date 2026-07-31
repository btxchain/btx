# MatMul v4.7 trusted RPC/archive mirrors

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
  sign (chain, block hash, height, v4, Profile 1)
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

The domain-separated version-1 statement commits to:

- the genesis hash as chain identifier;
- block header hash;
- exact block height;
- MatMul major version 4; and
- Profile 1.

Signatures use canonical compressed secp256k1 keys and strict DER/low-S ECDSA.
The store verifies the statement against the local block index and configured
chain before counting it. A signer contributes at most one vote to a block,
and quorum is `M` distinct members of the configured `N` keys.

Wrong-chain, wrong-height, wrong-hash, non-member, duplicate, malformed, and
invalid signatures do not count. Relayers have no authority: an attestation
can arrive from any peer because only the configured signature matters.

## Roles and service capabilities

- `-matmulvalidation=consensus` performs local authority as before. With a
  signing key and serving enabled, it may advertise
  `NODE_MATMUL_ATTESTATION_ARCHIVE`.
- `-matmulvalidation=trusted` performs the trusted-mirror policy, advertises
  `NODE_MATMUL_TRUSTED_MIRROR`, and never advertises
  `NODE_MATMUL_CONSENSUS`.
- The archive-provider and trusted-consumer bits are deliberately different.
  Both are unauthenticated routing hints; signatures remain mandatory.

Trusted mode is accepted on mainnet only with a valid nonempty signer set and
threshold. `economic` and `spv` remain prohibited on mainnet.

## Example: one GPU archive and three HA RPC mirrors

Generate a dedicated online attestation key. Put its WIF on the GPU archive in
a permission-restricted file. Distribute only its compressed public key to the
mirrors.

GPU archive:

```ini
matmulvalidation=consensus
matmulrcexecution=strict-device
matmultrustedpubkey=02...compressed-public-key
matmulattestationsignerkeyfile=/secure/btx/matmul-attestor.wif
matmulattestationserve=1
prune=0
```

Each VPS RPC mirror:

```ini
matmulvalidation=trusted
matmultrustedpubkey=02...compressed-public-key
matmultrustedthreshold=1
matmultrustedwaitms=30000
connect=<gpu-archive-address>
server=1
prune=0
txindex=1
```

Use `rpcbind`, `rpcallowip`, firewalling, authentication, and TLS/reverse-proxy
policy appropriate to the deployment. Trusted MatMul mode does not relax RPC
security.

For better fault and compromise tolerance, deploy three independent archive
signers and configure the mirrors with all three public keys plus:

```ini
matmultrustedthreshold=2
```

The mirrors can connect to all providers. One provider being offline or one key
being compromised then does not independently decide a verdict.

## Lifecycle

1. The archive runs authoritative local ExactReplay.
2. Only a successful locally persisted ExactReplay status permits signing.
3. A trusted mirror receiving a Profile-1 full block requests attestations
   from archive-provider peers while the body enters bounded validation.
4. The validation worker waits up to `-matmultrustedwaitms`.
5. On quorum, the process-local replay memo is populated and ordinary
   `ProcessNewBlock` runs all body, transaction, script, state, and chain
   checks.
6. Authenticated chainwork is assigned only after both quorum and complete-body
   validation succeed.
7. Timeout, cancellation, missing quorum, or local processing failure leaves
   the block retryable. It does not mark it invalid, cache a negative verdict,
   or punish the announcing peer.

Near-tip and historical full-block downloads request the same signed sidecars.
An archive can regenerate a historical attestation after restart only where its
block index durably records its own successful ExactReplay.

## Persistence and key rotation

The mirror's attestation store and replay memo are deliberately process-local.
The block index may retain
`BLOCK_TRUSTED_REPLAY_ATTESTED` for operator audit, but that bit is never read
as authority after restart. New blocks, and historical blocks that validation
actually revisits, must fetch/import signatures satisfying the current signer
set and threshold.

Already-connected `BLOCK_VALID_SCRIPTS` chainstate is not automatically
replayed merely because the process restarted. Therefore signer/threshold
rotation is prospective by default. To apply a new trust policy retroactively,
the operator must deliberately reindex/revalidate from the chosen height; that
revalidation cannot use the old audit bit as authority. Operators can transfer
a current-policy signed bundle with:

```bash
/path/to/btx-cli getmatmulattestations <blockhash>
/path/to/btx-cli submitmatmulattestations '["<serialized-attestation>", ...]'
```

`exportmatmulattestations` and `importmatmulattestations` are aliases for those
commands. `getmatmultrustedstatus` reports role, threshold, retained objects,
quorums, rejects, duplicates, and timeouts.

## P2P and resource limits

`getmmattest` requests one hash. `mmattest` carries at most 16 attestations and
has a 16 KiB payload cap before vector allocation. The receiver requires a
locally known Profile-1 index entry and independently checks every signature.
Per-peer request and inbound-object token buckets, a bounded outstanding-hash
map, bounded core store, TTL eviction, and bounded unsolicited relay prevent
the sidecar protocol from becoming an allocation or amplification path.

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
- Prefer M-of-N independent keys for a production fleet.
- If a GPU/provider is unhealthy, stop archive attestation service until the
  validator again completes authoritative ExactReplay. Never sign from a
  trusted mirror or from a device failure.
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
