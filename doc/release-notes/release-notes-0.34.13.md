# BTX 0.34.13rc1 — Trusted-mirror bounded recovery

**Status:** release candidate. `CLIENT_VERSION` is **0.34.13** with
`CLIENT_VERSION_RC=1` and `CLIENT_VERSION_IS_RELEASE=false`. P2P
subversion is `/BTX:0.34.13/`. The bounded-recovery work below is not a
consensus change. The HTLC claim leaf is.

A trusted mirror on `-reorgpolicy=bounded` could livelock when an
authenticated competing prefix was deeper than the normal park depth of
6 but not yet eligible for bounded recovery. Automatic selection unparked
that prefix, `ActivateBestChainStep` parked it again, and the same
selection ran immediately. A separate stall left the mirror unable to
request the next missing body, because acquisition treated ExactReplay as
the only usable authority and a trusted mirror does not set that bit.

0.34.13rc1 makes automatic unpark follow the bounded transition decision.
A no-progress policy park yields instead of retrying the same selection
while `cs_main` is held. Trusted-mirror recovery accepts a body that is
transaction-valid and covered by the current signed frontier. Only that
registered, higher-work, frontier-covered tower may be fetched while it
is parked, and a later batch on the same tower may continue when the
parent is not yet connected. Consensus mode stays exact-only. Manual
deep-reorg authority, park depth, and the 72-block recovery ceiling are
unchanged.

## Pay With Compute

0.34.13rc1 adds PWC/1, an off-consensus way to quote access in frozen
Profile-1 compute (`btx-rc-p1e-v1`) instead of money. One P1E is one
ExactReplay episode of that profile, accounted as 1,000,000 integer
`p1e_microunits`. A Compute Passport is self-attested performance evidence.
A fresh qualification challenge is exact, single-use, and replay-protected.
Useful jobs produce issuer-signed receipts. Balances are derived inside one
ComputeAgreement. PREPAID and PRO_RATA schedules are both supported. An
agreement can name a third-party scheduler and receipt issuer so contributed
work can benefit a different project. The resulting ComputeAccessGrant is an
application entitlement, not a LocalCapabilityGrant and not a wallet
authority.

This does not change block validity, headers, chainwork, difficulty,
activation heights, issuance, wallet balances, or `automatic_spend_atoms`.
The regtest toy profile `btx-rc-p1e-toy-v1` cannot settle a mainnet agreement.
The existing MatMul service challenge is unchanged. There is no transferable
compute token and no remote inference endpoint. This remains a release
candidate: `CLIENT_VERSION_IS_RELEASE=false`.

## P2MR HTLC

Thanks to **bs1812** for a private review of the SHA-256 HTLC
(`buildhtlcclaim` / `buildhtlcrefund`).

New `htlc_sha256` claim leaves require a 32-byte preimage in the script.
A lock funded earlier can still be spent with a 32-byte preimage.
`deriveaddresses` will not create a new HASH160 `htlc_tx()` or legacy
`htlc()` address, and those descriptors cannot be set active. `refund(0)`
is rejected, and the claim key and the refund key must be different.

`buildhtlcclaim` notes that the claim path has no deadline: after the
refund timeout, either spend can be valid and the one that pays more
confirms. `buildhtlcrefund` notes that nLockTime L confirms in the
following block, not in block L. Both spends signal replacement. The
claim uses nLockTime 0, so it can still be mined immediately. The
refund sequence stays non-final, so its timeout still applies.

A CPU-only regtest node in the default consensus MatMul mode stops
connecting blocks once ExactReplay is required. Startup says so.
`-matmulvalidation=economic` is the local-test setting; transaction and
script checks are unchanged. Do not use it on mainnet.
