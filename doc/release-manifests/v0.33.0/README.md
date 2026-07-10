# BTX 0.33.0 release-candidate evidence

This directory records the machine-readable inputs for the proposed mainnet
v0.33.0 hardening and fast-start snapshot refresh.

- Snapshot base: height `155700`
- Base hash: `b5ea1fb02d12e1cfa4bbc5ccc4946ca026ad4a5f270b99a0816aa95853306c3d`
- Snapshot file version: `9`
- Snapshot size: `448392435` bytes
- Snapshot SHA-256: `e0fb6d34852a7f0ac649dfaa9e4a50a1fa5bcde7ba97475ef3bf62f4175fc69e`
- Producer: an existing canonical archive node, with `btxd` kept online
- Cross-check: three independent canonical archive nodes returned the same
  block hash for height `155700`

The 448 MB `snapshot.dat` artifact is intentionally stored outside Git. The
checked-in snapshot and hardening manifests are reviewable release inputs.
The final multi-platform bundle must generate and sign a new `SHA256SUMS`
after every binary and snapshot asset is staged; candidate-only checksum or
key material is deliberately not committed here.

A disposable v0.33.0 staging node successfully loaded all `64,096`
coins, activated base height `155,700`, restored the pinned shielded state, and
retained the snapshot chainstate across an offline restart. Final public
certification must repeat the same activation/restart procedure with a clean
binary built from the exact merged `btxchain/btx` release commit.

The final bundle must be signed by the authorized public-release key and must
pass the fingerprint gate in the release tooling before publication.
