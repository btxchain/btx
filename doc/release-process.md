Release Process
====================

## Branch updates

### Before every release candidate

* Update release candidate version in `CMakeLists.txt` (`CLIENT_VERSION_RC`).
* Update manpages (after rebuilding the binaries), see [gen-manpages.py](/contrib/devtools/README.md#gen-manpagespy).
* Update `btx.conf` template content and commit changes if they exist, see [gen-btx-node-conf.sh](/contrib/devtools/README.md#gen-btx-node-confsh).

### Before every major and minor release

* Update [bips.md](bips.md) to account for changes since the last release.
* Update version in `CMakeLists.txt` (don't forget to set `CLIENT_VERSION_RC` to `0`).
* Update manpages (see previous section)
* Write release notes (see "Write the release notes" below) in doc/release-notes.md. If necessary,
  archive the previous release notes as doc/release-notes/release-notes-${VERSION}.md.

### Before every major release

* On both the master branch and the new release branch:
  - update `CLIENT_VERSION_MAJOR` in [`CMakeLists.txt`](../CMakeLists.txt)
* On the new release branch in [`CMakeLists.txt`](../CMakeLists.txt)(see [this commit](https://github.com/bitcoin/bitcoin/commit/742f7dd)):
  - set `CLIENT_VERSION_MINOR` to `0`
  - set `CLIENT_VERSION_BUILD` to `0`
  - set `CLIENT_VERSION_IS_RELEASE` to `true`

#### Before branch-off

* Update translations see [translation_process.md](/doc/translation_process.md#synchronising-translations).
* Update hardcoded [seeds](/contrib/seeds/README.md), see [this pull request](https://github.com/bitcoin/bitcoin/pull/27488) for an example.
* Update the following variables in [`src/kernel/chainparams.cpp`](/src/kernel/chainparams.cpp) for mainnet, testnet, and signet:
  - Prefer generating the hardening tuple with `/scripts/update_chain_hardening_manifest.py`:
    - Example:
      - `python3 scripts/update_chain_hardening_manifest.py --btx-cli build-btx/bin/btx-cli --chain main --rpc-arg=-datadir=<canonical-node-datadir> --rpc-arg=-rpcuser=<user> --rpc-arg=-rpcpassword=<pass> --output /tmp/mainnet-hardening.json`
    - The manifest contains a ready-to-apply `cpp_snippet` for `nMinimumChainWork`, `defaultAssumeValid`, `checkpointData`, and `chainTxData`.
    - Mainnet guardrail: by default the script refuses anchors below height `50000` unless `--allow-low-anchor-height` is explicitly provided.
    - If you are also generating a rollback snapshot for a specific height, pass `--target-height <same-height>` so the hardening manifest and snapshot are derived from the same block by default.
  - Apply and verify the generated manifest with `/scripts/apply_chain_hardening_manifest.py`:
    - Apply:
      - `python3 scripts/apply_chain_hardening_manifest.py --manifest /tmp/mainnet-hardening.json --chainparams src/kernel/chainparams.cpp --chain main`
    - Verify clean state:
      - `python3 scripts/apply_chain_hardening_manifest.py --manifest /tmp/mainnet-hardening.json --chainparams src/kernel/chainparams.cpp --chain main --check`
    - The apply step enforces genesis-hash parity to prevent accidental cross-chain hardening updates.
  - `m_assumed_blockchain_size` and `m_assumed_chain_state_size` with the current size plus some overhead (see
    [this](#how-to-calculate-assumed-blockchain-and-chain-state-size) for information on how to calculate them).
  - The following updates should be reviewed with `reindex-chainstate` and `assumevalid=0` to catch any defect
    that causes rejection of blocks in the past history.
  - `chainTxData` with statistics about the transaction count and rate. Use the output of the `getchaintxstats` RPC with an
    `nBlocks` of 4096 (28 days) and a `bestblockhash` of the selected final block hash; by default that is RPC `getbestblockhash`, but when generating release hardening for a historical rollback snapshot height use `scripts/update_chain_hardening_manifest.py --target-height <height>` so `bestblockhash` resolves to that same height; see
    [this pull request](https://github.com/bitcoin/bitcoin/pull/28591) for an example. Reviewers can verify the results by running
    `getchaintxstats <window_block_count> <window_final_block_hash>` with the `window_block_count` and `window_final_block_hash` from your output.
  - `defaultAssumeValid` with the output of RPC `getblockhash` using the `height` of `window_final_block_height` above
    (and update the block height comment with that height), taking into account the following:
    - On mainnet, the selected value must not be orphaned, so it may be useful to set the height two blocks back from the tip.
    - Testnet should be set with a height some tens of thousands back from the tip, due to reorgs there.
  - `nMinimumChainWork` with the "chainwork" value of RPC `getblockheader` using the same height as that selected for the previous step.
  - `m_assumeutxo_data` array should be appended to with the values returned by the BTX helper script:
    - `python3 contrib/devtools/generate_assumeutxo.py --btx-cli ./build-btx/bin/btx-cli --chain main --snapshot /tmp/snapshot.dat --snapshot-type rollback --rollback <height or hash> --rpc-arg=-datadir=<canonical-node-datadir> --rpc-arg=-rpcuser=<user> --rpc-arg=-rpcpassword=<pass> --json-out /tmp/snapshot.report.json --manifest-out /tmp/snapshot.manifest.json`
    - the generated JSON contains a ready-to-paste `chainparams_snippet`; the compact manifest is the published snapshot receipt
    - publish `snapshot.dat` together with `snapshot.manifest.json`
    - include both files in `SHA256SUMS`, and sign that file as `SHA256SUMS.asc` using the same release-process expectations as the binary payloads
    - for BTX, the published snapshot must come from a build that includes the shielded snapshot appendix and must be verified with the assumeutxo functional path below before release
  - Use the release-bundling helpers in [BTX GitHub Release Automation](/doc/btx-github-release-automation.md) to stage the final release directory and upload the bundle to GitHub Releases once the binaries, snapshot, and checksum artifacts are ready.
    The same height considerations for `defaultAssumeValid` apply.
  - Preferred operator path once the builder and canonical-node inputs are ready:
    - `python3 scripts/release/cut_release.py --repo btxchain/btx --tag <tag> --release-name <title> --build-with-guix --generate-snapshot --rollback <height or hash> --btx-cli ./build-btx/bin/btx-cli --rpc-arg=-datadir=<canonical-node-datadir> --rpc-arg=-rpcuser=<user> --rpc-arg=-rpcpassword=<pass> --attestations-dir <path-to-guix.sigs>/<version> --sign-with <release-gpg-key> --body-file doc/release-notes.md --token-file <github.key> --publish --bundle-dir /tmp/btx-release-bundle`
    - this command runs the same bundle collector and publisher used below, but it also stitches the Guix outputs, snapshot generation, attestation staging, and GitHub publish contract into one operator workflow
    - if you are staging from already-built outputs instead of building in place, pass `--guix-output-dir <guix-build-version/output>` and omit `--build-with-guix`
  - Native CLI preview path when you intentionally want a non-Guix release track:
    - `python3 scripts/release/cut_local_release.py --repo btxchain/btx --tag <tag> --release-name <title> --platform-spec "macos-arm64;<path-to-btxd>;<path-to-btx-cli>" --platform-spec "linux-arm64;<path-to-btxd>;<path-to-btx-cli>" --platform-spec "linux-x86_64;<path-to-btxd>;<path-to-btx-cli>" --bundle-dir /tmp/btx-native-cli-release --token-file <github.key> --smoke-platform macos-arm64 --publish`
    - use this only for clearly labeled native-built CLI releases; it does not claim Guix reproducibility or signer attestation coverage
    - if you do not also pass snapshot artifacts and a checksum signature, treat the output as a binary-install track rather than a full download-and-go release
  - Assemble the final fast-start bundle after the multi-architecture build finishes:
    - `python3 scripts/release/collect_release_assets.py --output-dir /tmp/btx-release-bundle --source <guix-output-dir>/x86_64-linux-gnu --source <guix-output-dir>/aarch64-linux-gnu --source <guix-output-dir>/x86_64-w64-mingw32 --source <guix-output-dir>/x86_64-apple-darwin --source <guix-output-dir>/arm64-apple-darwin --snapshot /tmp/snapshot.dat --snapshot-manifest /tmp/snapshot.manifest.json --release-tag <tag> --release-name <title> --sign-with <release-gpg-key>`
    - this step must target a fresh output directory and produces the single directory that should be uploaded to the GitHub release page: binaries, snapshot, manifests, `SHA256SUMS`, and `SHA256SUMS.asc`
    - the collector now fails the staging step if any supported primary archive is missing, so a successful run implies the generated `btx-release-manifest.json` contains one `platform_assets` entry for each supported primary archive
    - if a `guix.sigs/<version>` directory is available, pass `--attestations-dir <path-to-guix.sigs>/<version>` so the final bundle also publishes signer-qualified attestation assets and records them in `attestation_assets`
  - Publish the bundle to GitHub Releases:
    - `python3 scripts/release/publish_github_release.py --repo btxchain/btx --tag <tag> --bundle-dir /tmp/btx-release-bundle --body-file <release-notes.md> --token-file <github.key> --publish`
    - the publisher now refuses bundles whose on-disk assets drift from `SHA256SUMS`, and it verifies `SHA256SUMS.asc` locally whenever the bundle manifest advertises a checksum signature, so it acts as a second contract check before upload
  - Smoke-test the published bundle contract before announcing the release:
    - `python3 contrib/faststart/btx-agent-setup.py --release-manifest /tmp/btx-release-bundle/btx-release-manifest.json --asset-base-url /tmp/btx-release-bundle --platform linux-x86_64 --install-dir /tmp/btx-faststart-smoke --json`
    - this verifies that the local bundle is consumable by the same agent-facing installer path used after publication; published remote URLs additionally require `SHA256SUMS.asc` unless an operator explicitly opts out with `--allow-unsigned-release`
  - Run the BTX assumeutxo validation matrix before release publication:
    - `python3 test/util/generate_assumeutxo_test.py`
    - `python3 test/util/apply_assumeutxo_report_test.py`
    - `python3 test/util/release_bundle_manifest_test.py`
    - `python3 test/util/btx_agent_setup_test.py`
    - `python3 test/util/publish_github_release_test.py`
    - `python3 test/functional/feature_assumeutxo.py --configfile=<build>/test/config.ini --cachedir=<cache-dir>`
    - `python3 test/functional/rpc_btx_difficulty_health.py --configfile=<build>/test/config.ini`
    - targeted restart/snapshot coverage in `test_btx` such as `validation_tests` and `validation_chainstatemanager_tests`
    - targeted MatMul service coverage in `test_btx` such as `matmul_mining_tests/*`
* Consider updating the headers synchronization tuning parameters to account for the chainparams updates.
  The optimal values change very slowly, so this isn't strictly necessary every release, but doing so doesn't hurt.
  - Update configuration variables in [`contrib/devtools/headerssync-params.py`](/contrib/devtools/headerssync-params.py):
    - Set `TIME` to the software's expected supported lifetime -- after this time, its ability to defend against a high bandwidth timewarp attacker will begin to degrade.
    - Set `MINCHAINWORK_HEADERS` to the height used for the `nMinimumChainWork` calculation above.
    - Check that the other variables still look reasonable.
  - Run the script. It works fine in CPython, but PyPy is much faster (seconds instead of minutes): `pypy3 contrib/devtools/headerssync-params.py`.
  - Paste the output defining `HEADER_COMMITMENT_PERIOD` and `REDOWNLOAD_BUFFER_SIZE` into the top of [`src/headerssync.cpp`](/src/headerssync.cpp).
- Clear the release notes and move them to the wiki (see "Write the release notes" below).
- Translations on Transifex:
    - Pull translations from Transifex into the master branch.
    - Create [a new resource](https://app.transifex.com/bitcoin/bitcoin/content/) named after the major version with the slug `qt-translation-<RRR>x`, where `RRR` is the major branch number padded with zeros. Use `src/qt/locale/bitcoin_en.xlf` to create it.
    - In the project workflow settings, ensure that [Translation Memory Fill-up](https://help.transifex.com/en/articles/6224817-setting-up-translation-memory-fill-up) is enabled and that [Translation Memory Context Matching](https://help.transifex.com/en/articles/6224753-translation-memory-with-context) is disabled.
    - Update the Transifex slug in [`.tx/config`](/.tx/config) to the slug of the resource created in the first step. This identifies which resource the translations will be synchronized from.
    - Make an announcement that translators can start translating for the new version. You can use one of the [previous announcements](https://app.transifex.com/bitcoin/communication/) as a template.
    - Change the auto-update URL for the resource to `master`, e.g. `https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/qt/locale/bitcoin_en.xlf`. (Do this only after the previous steps, to prevent an auto-update from interfering.)

#### After branch-off (on the major release branch)

- Update the versions.
- Create the draft, named "*version* Release Notes Draft", as a [collaborative wiki](https://github.com/bitcoin-core/bitcoin-devwiki/wiki/_new).
- Clear the release notes: `cp doc/release-notes-empty-template.md doc/release-notes.md`
- Create a pinned meta-issue for testing the release candidate (see [this issue](https://github.com/bitcoin/bitcoin/issues/27621) for an example) and provide a link to it in the release announcements where useful.
- Translations on Transifex
    - Change the auto-update URL for the new major version's resource away from `master` and to the branch, e.g. `https://raw.githubusercontent.com/bitcoin/bitcoin/<branch>/src/qt/locale/bitcoin_en.xlf`. Do not forget this or it will keep tracking the translations on master instead, drifting away from the specific major release.
- Prune inputs from the qa-assets repo (See [pruning
  inputs](https://github.com/bitcoin-core/qa-assets#pruning-inputs)).

#### Before final release

- Merge the release notes from [the wiki](https://github.com/bitcoin-core/bitcoin-devwiki/wiki/) into the branch.
- Ensure the "Needs release note" label is removed from all relevant pull
  requests and issues:
  https://github.com/bitcoin/bitcoin/issues?q=label%3A%22Needs+release+note%22

#### Tagging a release (candidate)

To tag the version (or release candidate) in git, use the `make-tag.py` script from [bitcoin-maintainer-tools](https://github.com/bitcoin-core/bitcoin-maintainer-tools). From the root of the repository run:

    ../bitcoin-maintainer-tools/make-tag.py v(new version, e.g. 25.0)

This will perform a few last-minute consistency checks in the build system files, and if they pass, create a signed tag.

## BTX release-reference boundary

The steps above are the BTX-specific release playbook for publishing
fast-start validating-node bundles, assumeutxo snapshots, and GitHub release
assets.

The remaining sections in this document are preserved as upstream reference
material. They are useful when cross-checking historical maintainer workflows,
but they are not the primary BTX release instructions. For BTX releases, treat
`doc/btx-github-release-automation.md`, `doc/btx-download-and-go.md`, and
`contrib/faststart/README.md` as the active operator-facing docs.

## Building

### First time / New builders

Install Guix using one of the installation methods detailed in
[contrib/guix/INSTALL.md](/contrib/guix/INSTALL.md).

Check out the source code in the following directory hierarchy.

    cd /path/to/your/toplevel/build
    git clone https://github.com/bitcoin-core/guix.sigs.git
    git clone https://github.com/bitcoin-core/bitcoin-detached-sigs.git
    git clone https://github.com/bitcoin/bitcoin.git

### Write the release notes

Open a draft of the release notes for collaborative editing at https://github.com/bitcoin-core/bitcoin-devwiki/wiki.

For the period during which the notes are being edited on the wiki, the version on the branch should be wiped and replaced with a link to the wiki which should be used for all announcements until `-final`.

Generate list of authors:

    git log --format='- %aN' v(current version, e.g. 25.0)..v(new version, e.g. 25.1) | grep -v 'merge-script' | sort -fiu

### Setup and perform Guix builds

Checkout the Bitcoin Core version you'd like to build:

```sh
pushd ./bitcoin
SIGNER='(your builder key, ie bluematt, sipa, etc)'
VERSION='(new version without v-prefix, e.g. 25.0)'
git fetch origin "v${VERSION}"
git checkout "v${VERSION}"
popd
```

Ensure your guix.sigs are up-to-date if you wish to `guix-verify` your builds
against other `guix-attest` signatures.

```sh
git -C ./guix.sigs pull
```

### Create the macOS SDK tarball (first time, or when SDK version changes)

Create the macOS SDK tarball, see the [macdeploy
instructions](/contrib/macdeploy/README.md#sdk-extraction) for
details.

### Build and attest to build outputs

Follow the relevant Guix README.md sections:
- [Building](/contrib/guix/README.md#building)
- [Attesting to build outputs](/contrib/guix/README.md#attesting-to-build-outputs)

### Verify other builders' signatures to your own (optional)

- [Verifying build output attestations](/contrib/guix/README.md#verifying-build-output-attestations)

### Commit your non codesigned signature to guix.sigs

```sh
pushd ./guix.sigs
git add "${VERSION}/${SIGNER}"/noncodesigned.SHA256SUMS{,.asc}
git commit -m "Add attestations by ${SIGNER} for ${VERSION} non-codesigned"
popd
```

Then open a Pull Request to the [guix.sigs repository](https://github.com/bitcoin-core/guix.sigs).

## Codesigning

### macOS codesigner only: Create detached macOS signatures (assuming [signapple](https://github.com/achow101/signapple/) is installed and up to date with master branch)

In the `guix-build-${VERSION}/output/x86_64-apple-darwin` and `guix-build-${VERSION}/output/arm64-apple-darwin` directories:

    tar xf bitcoin-${VERSION}-${ARCH}-apple-darwin-codesigning.tar.gz
    ./detached-sig-create.sh /path/to/codesign.p12 /path/to/AuthKey_foo.p8 uuid
    Enter the keychain password and authorize the signature
    signature-osx.tar.gz will be created

### Windows codesigner only: Create detached Windows signatures

In the `guix-build-${VERSION}/output/x86_64-w64-mingw32` directory:

    tar xf bitcoin-${VERSION}-win64-codesigning.tar.gz
    ./detached-sig-create.sh /path/to/codesign.key
    Enter the passphrase for the key when prompted
    signature-win.tar.gz will be created

### Windows and macOS codesigners only: test code signatures
It is advised to test that the code signature attaches properly prior to tagging by performing the `guix-codesign` step.
However if this is done, once the release has been tagged in the bitcoin-detached-sigs repo, the `guix-codesign` step must be performed again in order for the guix attestation to be valid when compared against the attestations of non-codesigner builds. The directories created by `guix-codesign` will need to be cleared prior to running `guix-codesign` again.

### Windows and macOS codesigners only: Commit the detached codesign payloads

```sh
pushd ./bitcoin-detached-sigs
# checkout or create the appropriate branch for this release series
git checkout --orphan <branch>
# if you are the macOS codesigner
rm -rf osx
tar xf signature-osx.tar.gz
# if you are the windows codesigner
rm -rf win
tar xf signature-win.tar.gz
git add -A
git commit -m "<version>: {osx,win} signature for {rc,final}"
git tag -s "v${VERSION}" HEAD
git push the current branch and new tag
popd
```

### Non-codesigners: wait for Windows and macOS detached signatures

- Once the Windows and macOS builds each have 3 matching signatures, they will be signed with their respective release keys.
- Detached signatures will then be committed to the [bitcoin-detached-sigs](https://github.com/bitcoin-core/bitcoin-detached-sigs) repository, which can be combined with the unsigned apps to create signed binaries.

### Create the codesigned build outputs

- [Codesigning build outputs](/contrib/guix/README.md#codesigning-build-outputs)

### Verify other builders' signatures to your own (optional)

- [Verifying build output attestations](/contrib/guix/README.md#verifying-build-output-attestations)

### Commit your codesigned signature to guix.sigs (for the signed macOS/Windows binaries)

```sh
pushd ./guix.sigs
git add "${VERSION}/${SIGNER}"/all.SHA256SUMS{,.asc}
git commit -m "Add attestations by ${SIGNER} for ${VERSION} codesigned"
popd
```

Then open a Pull Request to the [guix.sigs repository](https://github.com/bitcoin-core/guix.sigs).

## After 6 or more people have guix-built and their results match

After verifying signatures, combine the `all.SHA256SUMS.asc` file from all signers into `SHA256SUMS.asc`:

```bash
cat "$VERSION"/*/all.SHA256SUMS.asc > SHA256SUMS.asc
```


- Upload to the bitcoincore.org server:
    1. The contents of each `./bitcoin/guix-build-${VERSION}/output/${HOST}/` directory.

       Guix will output all of the results into host subdirectories, but the SHA256SUMS
       file does not include these subdirectories. In order for downloads via torrent
       to verify without directory structure modification, all of the uploaded files
       need to be in the same directory as the SHA256SUMS file.

       Wait until all of these files have finished uploading before uploading the SHA256SUMS(.asc) files.

    2. The `SHA256SUMS` file

    3. The `SHA256SUMS.asc` combined signature file you just created.

- After uploading release candidate binaries, notify the bitcoin-core-dev mailing list and
  bitcoin-dev group that a release candidate is available for testing. Include a link to the release
  notes draft.

- The server will automatically create an OpenTimestamps file and torrent of the directory.

- Optionally help seed this torrent. To get the `magnet:` URI use:

  ```sh
  transmission-show -m <torrent file>
  ```

  Insert the magnet URI into the announcement sent to mailing lists. This permits
  people without access to `bitcoincore.org` to download the binary distribution.
  Also put it into the `optional_magnetlink:` slot in the YAML file for
  bitcoincore.org.

- Archive the release notes for the new version to `doc/release-notes/release-notes-${VERSION}.md`
  (branch `master` and branch of the release).

- Update the bitcoincore.org website

  - blog post

  - maintained versions [table](https://github.com/bitcoin-core/bitcoincore.org/commits/master/_includes/posts/maintenance-table.md)

  - RPC documentation update

      - See https://github.com/bitcoin-core/bitcoincore.org/blob/master/contrib/doc-gen/


- Update repositories

  - Delete post-EOL [release branches](https://github.com/bitcoin/bitcoin/branches/all) and create a tag `v${branch_name}-final`.

  - Delete ["Needs backport" labels](https://github.com/bitcoin/bitcoin/labels?q=backport) for non-existing branches.

  - Update packaging repo

      - Push the flatpak to flathub, e.g. https://github.com/flathub/org.bitcoincore.bitcoin-qt/pull/2

      - Push the snap, see https://github.com/bitcoin-core/packaging/blob/main/snap/local/build.md

  - Create a [new GitHub release](https://github.com/bitcoin/bitcoin/releases/new) with a link to the archived release notes

- Announce the release:

  - bitcoin-dev and bitcoin-core-dev mailing list

  - Bitcoin Core announcements list https://bitcoincore.org/en/list/announcements/join/

  - Bitcoin Core Twitter https://twitter.com/bitcoincoreorg

  - Celebrate

### Additional information

#### <a name="how-to-calculate-assumed-blockchain-and-chain-state-size"></a>How to calculate `m_assumed_blockchain_size` and `m_assumed_chain_state_size`

Both variables are used as a guideline for how much space the user needs on their drive in total, not just strictly for the blockchain.
Note that all values should be taken from a **fully synced** node and have an overhead of 5-10% added on top of its base value.

To calculate `m_assumed_blockchain_size`, take the size in GiB of these directories:
- For `mainnet` -> the data directory, excluding the `/testnet3`, `/testnet4`, `/signet`, and `/regtest` directories and any overly large files, e.g. a huge `debug.log`
- For `testnet` -> `/testnet3`
- For `testnet4` -> `/testnet4`
- For `signet` -> `/signet`

To calculate `m_assumed_chain_state_size`, take the size in GiB of these directories:
- For `mainnet` -> `/chainstate`
- For `testnet` -> `/testnet3/chainstate`
- For `testnet4` -> `/testnet4/chainstate`
- For `signet` -> `/signet/chainstate`

Notes:
- When taking the size for `m_assumed_blockchain_size`, there's no need to exclude the `/chainstate` directory since it's a guideline value and an overhead will be added anyway.
- The expected overhead for growth may change over time. Consider whether the percentage needs to be changed in response; if so, update it here in this section.
