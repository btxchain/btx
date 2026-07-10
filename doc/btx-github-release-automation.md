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

The staging repository is `btxchain/btx-node`, while public release assets are
published from `btxchain/btx`. The manual workflow therefore exposes a
`release_repository` input that defaults to `btxchain/btx`; keep `publish`
disabled while validating a private staging branch. A public publish is
deliberately impossible from the staging checkout: the exact source repository
and commit recorded in the bundle must exist in and match `btxchain/btx`.

Example:

```bash
python3 scripts/release/cut_release.py \
  --repo btxchain/btx \
  --tag v0.33.0 \
  --release-name "BTX 0.33.0" \
  --source-repository btxchain/btx \
  --source-commit "$(git rev-parse HEAD)" \
  --build-with-guix \
  --generate-snapshot \
  --rollback 60776 \
  --btx-cli ./build-btx/bin/btx-cli \
  --rpc-arg=-datadir=/srv/btx-main \
  --attestations-dir ../guix.sigs/29.2 \
  --sign-with release-signing-key \
  --expected-signing-fingerprint <authorized-40-hex-fingerprint> \
  --body-file doc/release-notes.md \
  --token-file /path/to/github.key \
  --publish \
  --bundle-dir /tmp/btx-release-bundle
```

The datadir example uses the node's protected RPC cookie. Do not put
`rpcuser`, `rpcpassword`, or `rpcauth` values in workflow inputs or shell
history.

By default, the script looks for Guix outputs under
`guix-build-<version>/output/` and for attestations under
`../guix.sigs/<version>/`, where `<version>` is derived from the tag.
Override those paths when your release runner stores them elsewhere.

## Bundle assets

Use `scripts/release/collect_release_assets.py` to stage a publishable bundle:

```bash
python3 scripts/release/collect_release_assets.py \
  --output-dir /tmp/btx-release \
  --source /path/to/guix-build-29.2/output/x86_64-linux-gnu \
  --source /path/to/guix-build-29.2/output/x86_64-linux-gnu-cuda12 \
  --source /path/to/guix-build-29.2/output/aarch64-linux-gnu \
  --source /path/to/guix-build-29.2/output/arm64-apple-darwin \
  --snapshot /tmp/snapshot.dat \
  --snapshot-manifest /tmp/snapshot.manifest.json \
  --release-tag v0.33.0 \
  --release-name "BTX 0.33.0" \
  --source-repository btxchain/btx \
  --source-commit "$(git rev-parse HEAD)" \
  --sign-with release-signing-key
```

The collector flattens the source files into one release directory, adds the
snapshot assets under their published names, stages `SHA256SUMS.asc` when
requested, emits `btx-release-manifest.json`, and writes `SHA256SUMS` over the
final bundle. Use `--checksum-signature /path/to/SHA256SUMS.asc` if the
signature is produced externally instead of by the collector itself. By
default, the collector requires the same production download matrix used by the
stable 0.32.x releases (`linux-x86_64`, `linux-x86_64-cuda12`,
`linux-arm64`, `macos-arm64`) before it will stage a publishable bundle.
Optional CUDA 13, Windows, and macOS x86_64 archives are included when present,
or can be made mandatory for a specific release with additional
`--required-platform` flags. See [`doc/linux-release-builds.md`](linux-release-builds.md)
for the Linux CPU/CUDA hardware and driver matrix.

If you also pass `--attestations-dir /path/to/guix.sigs/<version>`, the
collector now stages matching per-signer Guix attestation files as
signer-qualified assets such as
`guix-attestations-alice-noncodesigned.SHA256SUMS.asc`. The generated release
manifest records those assets in `attestation_assets`, so release provenance is
published alongside the binaries without filename collisions across signers.

The generated release manifest now includes a `platform_assets` map for the
primary Linux CPU, Linux CUDA, macOS, and Windows archives.
`contrib/faststart/btx-agent-setup.py` uses that map to choose the right binary
archive automatically for a download-and-go install. It also includes
`attestation_assets` when signer attestations are staged, which is useful for
operator-facing provenance workflows even though the installer itself ignores
those assets.

## Publish assets

Use `scripts/release/publish_github_release.py` to create or update a GitHub
release:

```bash
python3 scripts/release/publish_github_release.py \
  --repo btxchain/btx \
  --tag v0.33.0 \
  --target-commit "$(git rev-parse HEAD)" \
  --expected-signing-fingerprint <authorized-40-hex-fingerprint> \
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
checksum contract, and that the public bundle's `SHA256SUMS.asc` verifies
under the explicitly authorized fingerprint. For `btxchain/btx`, it also
requires the manifest repository/tag/commit to match the command, confirms the
exact commit exists in the target repository, resolves any existing tag to the
same commit, and makes that commit the tag target. Public releases are staged
as drafts, uploaded and re-listed for name/size completeness, and only then
made visible. Already-public releases are immutable unless an operator invokes
the explicit recovery mode.

After publication, smoke-test the operator install path against the staged
bundle contract:

```bash
python3 contrib/faststart/btx-agent-setup.py \
  --repo btxchain/btx \
  --release-tag v0.33.0 \
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

Dispatch values are mapped into environment variables and passed as data,
never interpolated into shell source. The job checks out only protected `main`,
runs behind the protected `btx-release` GitHub Environment, pins third-party
Actions by commit, does not print its assembled command, and rejects inline RPC
credentials. Build/collect receives no release secrets; the GPG passphrase is
available only to `sign_release_bundle.py`, and the release PAT only to the
final publisher step. The authorized fingerprint comes from the protected
environment variable `BTX_RELEASE_SIGNING_FINGERPRINT`, not from a dispatch
input.

When reproducing this separation locally, first collect the unsigned bundle,
then run:

```bash
python3 scripts/release/sign_release_bundle.py \
  --bundle-dir /tmp/btx-release \
  --sign-with <release-key> \
  --expected-signing-fingerprint <authorized-40-hex-fingerprint> \
  --gpg-passphrase-env BTX_GPG_PASSPHRASE
```

The signer rewrites the manifest/checksum contract, produces the detached
signature, verifies the exact fingerprint, and restores the unsigned bundle if
signing or verification fails.

## Native-built CLI release path

When you want to ship native-built CLI archives without Guix attestations, use
`scripts/release/cut_local_release.py` and pass the already-built `btxd` /
`btx-cli` pairs explicitly:

```bash
python3 scripts/release/cut_local_release.py \
  --repo <staging-owner/repository> \
  --tag v0.33.0 \
  --release-name "BTX 0.33.0" \
  --source-repository <staging-owner/repository> \
  --source-commit "$(git rev-parse HEAD)" \
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
staging release is unsigned and remote `btx-agent-setup.py` use will require
`--allow-unsigned-release`. The public `btxchain/btx` publisher never permits
an unsigned release and always requires an explicitly pinned signer.
