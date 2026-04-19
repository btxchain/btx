# BTX GitHub Release Automation

This repo now includes a small release-automation toolkit for shipping
precompiled BTX binaries together with the matching fast-start snapshot
artifacts.

There are now two release-cut entry points:

- `scripts/release/cut_release.py` for the full Guix/self-hosted release path
- `scripts/release/cut_local_release.py` for a native-built subset release such
  as `macos-arm64` plus `linux-arm64` when you need a practical CLI release
  before Guix or Windows artifacts are ready

## End-to-end release cut

Use `scripts/release/cut_release.py` when you want one operator command to:

- optionally run the primary-platform Guix build
- optionally generate `snapshot.dat` and `snapshot.manifest.json`
- stage binaries, snapshot artifacts, signed checksums, and guix attestations
  into one bundle directory
- validate the bundle against the GitHub publisher contract
- optionally publish the bundle to GitHub Releases

Example:

```bash
python3 scripts/release/cut_release.py \
  --repo btxchain/btx \
  --tag v0.29.5 \
  --release-name "BTX 0.29.5" \
  --build-with-guix \
  --generate-snapshot \
  --rollback 60776 \
  --btx-cli ./build-btx/bin/btx-cli \
  --rpc-arg=-datadir=/srv/btx-main \
  --rpc-arg=-rpcuser=release \
  --rpc-arg=-rpcpassword=secret \
  --attestations-dir ../guix.sigs/29.2 \
  --sign-with release-signing-key \
  --body-file doc/release-notes.md \
  --token-file /path/to/github.key \
  --publish \
  --bundle-dir /tmp/btx-release-bundle
```

By default, the script looks for Guix outputs under
`guix-build-<version>/output/` and for attestations under
`../guix.sigs/<version>/`, where `<version>` is derived from the tag.
Override those paths when your release runner stores them elsewhere.

## Bundle assets

Use `scripts/release/collect_release_assets.py` to stage a publishable bundle:

```bash
python3 scripts/release/collect_release_assets.py \
  --output-dir /tmp/btx-release \
  --source /path/to/guix-build-29.2/output/linux-x86_64 \
  --source /path/to/guix-build-29.2/output/linux-arm64 \
  --source /path/to/guix-build-29.2/output/windows-x86_64 \
  --source /path/to/guix-build-29.2/output/darwin-x86_64 \
  --source /path/to/guix-build-29.2/output/darwin-arm64 \
  --snapshot /tmp/snapshot.dat \
  --snapshot-manifest /tmp/snapshot.manifest.json \
  --release-tag v0.29.5 \
  --release-name "BTX 0.29.5" \
  --sign-with release-signing-key
```

The collector flattens the source files into one release directory, adds the
snapshot assets under their published names, stages `SHA256SUMS.asc` when
requested, emits `btx-release-manifest.json`, and writes `SHA256SUMS` over the
final bundle. Use `--checksum-signature /path/to/SHA256SUMS.asc` if the
signature is produced externally instead of by the collector itself. By
default, the collector now also requires the full primary platform matrix
(`linux-x86_64`, `linux-arm64`, `windows-x86_64`, `macos-x86_64`,
`macos-arm64`) before it will stage a publishable bundle.

If you also pass `--attestations-dir /path/to/guix.sigs/<version>`, the
collector now stages matching per-signer Guix attestation files as
signer-qualified assets such as
`guix-attestations-alice-noncodesigned.SHA256SUMS.asc`. The generated release
manifest records those assets in `attestation_assets`, so release provenance is
published alongside the binaries without filename collisions across signers.

The generated release manifest now includes a `platform_assets` map for the
primary Linux/macOS/Windows archives. `contrib/faststart/btx-agent-setup.py`
uses that map to choose the right binary archive automatically for a download-
and-go install. It also includes `attestation_assets` when signer attestations
are staged, which is useful for operator-facing provenance workflows even
though the installer itself ignores those assets.

## Publish assets

Use `scripts/release/publish_github_release.py` to create or update a GitHub
release:

```bash
python3 scripts/release/publish_github_release.py \
  --repo btxchain/btx \
  --tag v0.29.5 \
  --bundle-dir /tmp/btx-release \
  --token-file /path/to/github.key \
  --publish
```

The publisher accepts the token from `--token`, `--token-file`,
`BTX_GITHUB_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN`. Run with `--dry-run` first
if you want to verify the release payload without talking to GitHub. Under the
hood it uses the GitHub REST API via `curl`, which keeps the same token flow
usable in local ops automation. Before upload, it now verifies that every
bundle asset matches `SHA256SUMS`, that no stray files are present outside the
checksum contract, and that `SHA256SUMS.asc` verifies locally whenever the
bundle manifest advertises a checksum signature.

After publication, smoke-test the operator install path against the staged
bundle contract:

```bash
python3 contrib/faststart/btx-agent-setup.py \
  --repo btxchain/btx \
  --release-tag v0.29.5 \
  --preset service \
  --datadir /tmp/btx-service-smoke \
  --json
```

For published remote bundles, that installer path now rejects releases that do
not provide `SHA256SUMS.asc`, unless the operator explicitly passes
`--allow-unsigned-release`. If the repository or release is private, set
`BTX_GITHUB_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN` first so the installer can
authenticate the manifest and archive downloads while following GitHub's
browser-download redirects.

## Workflow validation

The `BTX Release Assets` workflow now has two roles:

- a GitHub-hosted validation job that smoke-tests the release helpers with a
  synthetic bundle, including guix attestation staging
- a manual self-hosted `cut release bundle` job that can run
  `scripts/release/cut_release.py` on a provisioned release runner and upload
  the resulting bundle as a workflow artifact before or during publication

When snapshot generation is enabled, that self-hosted workflow also uploads the
generated `snapshot.report.json` and `snapshot.manifest.json` as a separate
artifact. That gives maintainers the ready-to-apply assumeutxo report needed to
update `src/kernel/chainparams.cpp` from a runner that already has access to
the trusted synced node and release inputs.

The self-hosted job is intentionally parameterized around runner-local paths for
Guix outputs, snapshot artifacts, and guix.sigs state, because those release
inputs are too large or too sensitive to manufacture inside the workflow
itself.

## Native-built CLI release path

When you want to ship native-built CLI archives without Guix attestations, use
`scripts/release/cut_local_release.py` and pass the already-built `btxd` /
`btx-cli` pairs explicitly:

```bash
python3 scripts/release/cut_local_release.py \
  --repo btxchain/btx \
  --tag v0.29.5 \
  --release-name "BTX 0.29.5" \
  --bundle-dir /tmp/btx-native-cli-bundle \
  --platform-spec "macos-arm64;/path/to/macos/btxd;/path/to/macos/btx-cli" \
  --platform-spec "linux-arm64;/path/to/linux/btxd;/path/to/linux/btx-cli" \
  --body-file /path/to/release-notes.md \
  --token-file /path/to/github.key \
  --smoke-platform macos-arm64 \
  --publish
```

That flow packages the supplied binaries with the same helper payload used by
the normal BTX archives, stages a subset `platform_assets` release manifest,
dry-runs the publisher, optionally smoke-installs the bundle with
`btx-agent-setup.py`, and can then publish the release through the GitHub API.

If you omit `--snapshot` / `--snapshot-manifest`, the release is intentionally a
binary-only CLI track rather than a fast-start validating-node release.
Likewise, if you omit `--sign-with` and `--checksum-signature`, the resulting
release is unsigned and remote `btx-agent-setup.py` use will require
`--allow-unsigned-release`.
