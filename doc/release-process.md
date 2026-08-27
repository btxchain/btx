Release Process
====================

## Branch updates

### Before every release candidate

* Update release candidate version in `CMakeLists.txt` (`CLIENT_VERSION_RC`).
* Update manpages (after rebuilding the binaries), see [gen-manpages.py](/contrib/devtools/README.md#gen-manpagespy).
* Update `btx.conf` template content and commit changes if they exist, see [gen-bitcoin-conf.sh](/contrib/devtools/README.md#gen-bitcoin-confsh).
* **ZMQ is required on every shipped `btxd`.** Configure CPU, CUDA, and Metal
  release trees with `-DWITH_ZMQ=ON` (the CMake default is ON; pass it anyway).
  After the link, run `python3 scripts/release/verify_release_btxd.py <btxd> <btx-cli>`:
  Linux `ldd` must show `libzmq`; macOS must statically link `libzmq.a`,
  `libevent_*.a`, and `libomp.a` — `otool -L` must show **zero** `/opt/homebrew`
  or `/usr/local/opt` paths on both binaries. A Homebrew `libevent`/`libomp`
  dylib is not a shippable public artifact. CMake's configure summary must
  print `ZeroMQ ... ON` and, on macOS, `Libevent linkage ... static:`.
  Do not ship a binary that contains `-zmqpubhashblock` strings without linking
  libzmq — that is issues
  [#111](https://github.com/btxchain/btx/issues/111) (v0.33.3, closed by
  recutting one tarball while CMake still defaulted OFF) and
  [#122](https://github.com/btxchain/btx/issues/122) (v0.33.4.2 Linux CPU,
  the identical miss). Default ON plus this check is the durable fix;
  recutting one archive was not.
* Complete the Profile-1 ExactReplay golden corpus and seal described below.
  Any change under `CMakeLists.txt`, `cmake/`, `src/`, or `contrib/matmul-v4/`
  (except the inert manifest `.data` file) invalidates the previous seal.

## Profile-1 ExactReplay golden corpus and seal

0.34 is meant to be a final reference a third party can release from without
access to the original machines or keys. Guix (`contrib/guix/`) builds the
binaries; this section is the missing piece: how an outside maintainer
re-measures ExactReplay goldens and cuts the next seal. The corpus driver
(`contrib/matmul-v4/multi-gpu-golden-corpus.sh`) contains no WIF, keys, or
credentials. Policy detail lives in
[btx-matmul-v4.7-production-golden-policy.md](btx-matmul-v4.7-production-golden-policy.md).

### When a re-seal is required

Re-seal after **any BUILD_RELEVANT change**. The fingerprint is SHA-256 of
`git ls-tree -r --full-tree <revision> -- CMakeLists.txt cmake src contrib/matmul-v4`
with the single exclusion
`src/matmul/matmul_v4_rc_production_golden_manifest.data`.
That file is inert manifest bytes (CMake emits a numeric array; C++ parses a
strict schema), so excluding it is the only way sealing is not a fixed point.
Any other change in that scope — including a one-line compile fix — moves the
fingerprint and burns any corpus already recorded against the previous freeze.

CPU ExactReplay is not an independent production golden. The required cohort is
**CUDA and Metal**. HIP is optional; if supplied it must match exactly.

### Ordering: prove builds, then freeze, then measure

Do not cut a freeze and then discover that a target host cannot compile it.

1. Compile **every** release target on **every** corpus host until each is
   clean: `matmul-v4-rc-harness`, `btxd`, and `btx-cli`, all with
   `-DWITH_ZMQ=ON`. A first-ever Metal build of a tree often surfaces AppleClang
   errors (OpenMP structured-binding captures, designated NTTP arguments) that
   GCC/nvcc already accepted. Each of those fixes is BUILD_RELEVANT.
2. Only when every host has linked those three binaries, commit the freeze
   `F`, push it, and confirm the working tree is clean on BUILD_RELEVANT paths.
3. Compute the fingerprint of `F` (must be identical on every host):

   ```bash
   F="$(git rev-parse HEAD)"
   git ls-tree -r --full-tree "$F" -- CMakeLists.txt cmake src contrib/matmul-v4 \
     | grep -v "$(printf '\t')src/matmul/matmul_v4_rc_production_golden_manifest.data$" \
     | sha256sum   # macOS: shasum -a 256
   ```

4. Then run the corpora against that `F` and fingerprint. Never start a corpus
   against a freeze that is still accumulating compile fixes.

Freeze-then-discover-then-re-freeze discards every episode already measured.
The in-tree verifiers will also reject a dirty harness recorded under a clean
revision: the corpus script refuses a dirty BUILD_RELEVANT working tree.

Before the seal commit, both verifiers are **expected to FAIL** (stale
manifest revision / "build-relevant code changed after the measured freeze").
That is the pre-seal state, not a green light to skip them.

### Hardware a maintainer needs

| Backend | What you need | Notes |
|---|---|---|
| CUDA | Linux x86_64, NVIDIA GPU compute capability ≥ 8.0, a driver that matches the toolkit used to compile the harness, `nvcc` | 0.34 goldens were measured on Blackwell `sm_120` (RTX 5060 Ti class). Ampere/Ada may seal if the production path stays device-native (zero CPU fallback) and the digests match Metal. See [linux-release-builds.md](linux-release-builds.md). |
| Metal | Apple Silicon (arm64, M1 or later), macOS 14/15, Xcode clang, Homebrew `cmake` `ninja` `libomp` `zeromq` `boost` `libevent` | M1 works; newer chips are faster. If another `btxd` is already running on that Mac, compile the freeze tree at `-j1` so you do not starve it. |
| HIP | Optional. Only if you want a third provider in the cohort. | Must byte-match CUDA and Metal when present. |
| CPU | Not accepted as an independent production golden. | Portable ExactReplay remains the diagnostic oracle. |

Two hosts may run their corpora in parallel. They must pass the **same**
`--source-revision` (full 40-character `F`) and **same**
`--source-tree-fingerprint`. `validate_artifact` / the corpus merger reject
the whole run on `source_revision_mismatch` if those strings differ.

### Environment gotchas

**Apple Silicon / Homebrew**

```bash
export PATH="/opt/homebrew/bin:/usr/bin:$PATH"
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig"
export CMAKE_PREFIX_PATH="/opt/homebrew"
cmake -S . -B build-metal -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/opt/homebrew \
  -DWITH_ZMQ=ON \
  -DBTX_ENABLE_METAL=ON \
  -DBUILD_GUI=OFF -DBUILD_BENCH=OFF
```

Without `PKG_CONFIG_PATH` and `CMAKE_PREFIX_PATH`, CMake reports ZeroMQ
missing even when `brew install zeromq` succeeded. Prefer static `libzmq.a`
(CMake already does this on Apple) so the shipped `btxd` has **no Homebrew
zmq dylib**. Libevent and libomp must be static too (`libevent_core.a`,
`libomp.a`) — a dylib under `/opt/homebrew` will not launch on a clean Mac.
Verify:

```bash
otool -L build-metal/bin/btxd | grep homebrew   # must print nothing
otool -L build-metal/bin/btx-cli | grep homebrew
otool -L build-metal/bin/btxd | grep -i zmq     # must print nothing (static)
strings build-metal/bin/btxd | grep -F 'Enable publish hash block'
python3 scripts/release/verify_release_btxd.py \
  build-metal/bin/btxd build-metal/bin/btx-cli
```

AppleClang with `-fopenmp` cannot capture structured bindings in lambdas
("capturing a structured binding is not yet supported in OpenMP"). Copy the
binding to an ordinary local (`uint32_t column{item.first};`) before the
lambda. AppleClang also rejects designated initializers as non-type template
arguments (`AssignIntArgToVar<T, {.min = 0}>`); name a `constexpr` options
object instead. The macOS 15 SDK libc++ still lacks `std::jthread` /
`std::stop_token`; use `std::thread` plus an explicit stop flag.

**Linux CUDA**

Pass `-DWITH_ZMQ=ON`. `pkg-config --exists libzmq` must succeed in the same
environment that runs cmake (a user-local `libzmq.pc` is invisible unless
`PKG_CONFIG_PATH` is set). After link:

```bash
ldd build-cuda/bin/btxd | grep zmq    # must show libzmq
python3 scripts/release/verify_release_btxd.py build-cuda/bin/btxd
```

Do not `SIGKILL` a production `btxd` to free a GPU. Nice the corpus
(`nice -n 10`) if a live node shares the device.

### Exact corpus invocation

On each backend host, from a **clean** checkout of freeze `F`, with a harness
built from that checkout:

```bash
F=<40-char freeze commit>
FP=<64-char fingerprint of F>
OUT=doc/evidence/multi-gpu-profile1-goldens-YYYY-MM-DD

# CUDA host
contrib/matmul-v4/multi-gpu-golden-corpus.sh \
  --harness build-cuda/bin/matmul-v4-rc-harness \
  --backends cuda \
  --episodes 8 \
  --canary-nonce-start 1 \
  --source-revision "$F" \
  --source-tree-fingerprint "$FP" \
  --out-dir "$OUT" \
  --allow-partial

# Metal host (same F, same FP, same OUT name; copy CUDA raw JSON in or copy
# Metal raw JSON back — the merger reads OUT/raw/profile1-{cuda,metal}-8.json)
contrib/matmul-v4/multi-gpu-golden-corpus.sh \
  --harness build-metal/bin/matmul-v4-rc-harness \
  --backends metal \
  --episodes 8 \
  --canary-nonce-start 1 \
  --source-revision "$F" \
  --source-tree-fingerprint "$FP" \
  --out-dir "$OUT" \
  --allow-partial
```

`--allow-partial` is only legal while a **single** backend is still running.
Once both `raw/profile1-cuda-8.json` and `raw/profile1-metal-8.json` sit in the
same `$OUT` (copy with `scp`; do not edit JSON), rebuild the comparison
**without** `--allow-partial`:

```bash
contrib/matmul-v4/multi-gpu-golden-corpus.sh \
  --compare-only \
  --episodes 8 \
  --canary-nonce-start 1 \
  --source-revision "$F" \
  --source-tree-fingerprint "$FP" \
  --out-dir "$OUT"
```

The comparison must report `complete_multi_gpu_match=true`,
`allow_partial=false`, `required_for_manifest=["cuda","metal"]`. Never
hand-edit `source_revision` / `source_tree_fingerprint` in a JSON to make a
verifier pass — that falsifies evidence. If a compile fix landed after `F`,
go back to step 1 and cut a new freeze.

### Seal commit

One commit `S` after `F`. `S` may change only:

* `src/matmul/matmul_v4_rc_production_golden_manifest.data`
* files under `doc/` (the corpus JSON, `multi-gpu-digest-compare.json`, READMEs)

`git diff --name-only F..S` on BUILD_RELEVANT paths must be exactly the
manifest. `F` must be an ancestor of `S`. Then, on a **clean** tree:

```bash
python3 contrib/matmul-v4/verify-production-golden-seal.py seal --root .
python3 contrib/matmul-v4/verify-evidence-provenance.py --strict
```

Both must print PASS. `--strict` fails unbound fingerprints, revisions that
are not ancestors of HEAD, and stale historical exclusions. Do not commit `S`
until both pass. Do not tag or announce a release from a tree whose seal
verifiers fail.

### GPU qualification diagnostics

`production_qualified` / `peak_ready` is the AND of twenty bits on
`RCPeakReadyInputs` (`src/matmul/matmul_v4_rc_peak_ready.h`). A failure used
to yield only the string `peak_ready_prerequisites_incomplete`.
`DeriveRCPeakReady` now sets `deficit` to

`peak_ready_prerequisites_incomplete:<comma-separated false bits>`

so a maintainer can see which of the twenty conditions failed. The names are:

`v3_config_selected`, `production_dimensions`, `full_page_schedule`,
`real_m128_workload`, `canonical_packed_bank`, `native_provider_linked`,
`arch_backend_selected`, `exactness_selfqual_ok`, `bank_genuinely_resident`,
`native_tensor_executed`, `full_device_pipeline`, `no_per_barrier_host_sync`,
`no_cpu_fallback`, `no_dense_int8_as_native`, `no_scalar_cuda_as_native`,
`device_event_timing`, `cpu_gpu_byte_exact`, `production_provenance_recorded`,
`corruption_gate_ok`, `production_readiness_tests_pass`.

Inspect them by calling `FormatPeakReadyDeficit` / reading
`RCPeakReadyStatus.deficit` (datacenter probe logs concatenate this string).
An empty `deficit` is the only qualified state. `compiled == ready` is never
allowed: `MakeRCPeakReadyInputsFromEpisode` leaves several production latches
false until the corresponding campaign bits are actually set.

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
      - `python3 scripts/update_chain_hardening_manifest.py --btx-cli build-btx/bin/btx-cli --chain main --rpc-arg=-datadir=<canonical-node-datadir> --output /tmp/mainnet-hardening.json`
      - use the protected RPC cookie in that datadir; do not put RPC credentials in shell history or workflow inputs
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
    - `python3 contrib/devtools/generate_assumeutxo.py --btx-cli ./build-btx/bin/btx-cli --chain main --snapshot /tmp/snapshot.dat --snapshot-type rollback --rollback <height or hash> --rpc-arg=-datadir=<canonical-node-datadir> --json-out /tmp/snapshot.report.json --manifest-out /tmp/snapshot.manifest.json`
    - the generated JSON contains a ready-to-paste `chainparams_snippet`; the compact manifest is the published snapshot receipt and includes `snapshot_file_version` for troubleshooting
    - publish `snapshot.dat` together with `snapshot.manifest.json`
    - include both files in `SHA256SUMS`, and sign that file as `SHA256SUMS.asc` using the same release-process expectations as the binary payloads
    - for BTX, the published snapshot must come from a build that includes the shielded snapshot appendix and must be verified with the assumeutxo functional path below before release
  - Use the release-bundling helpers in [BTX GitHub Release Automation](/doc/btx-github-release-automation.md) to stage the final release directory and upload the bundle to GitHub Releases once the binaries, snapshot, and checksum artifacts are ready.
    The same height considerations for `defaultAssumeValid` apply.
  - Preferred operator path once the builder and canonical-node inputs are ready:
    - `python3 scripts/release/cut_release.py --repo btxchain/btx --tag <tag> --release-name <title> --source-repository btxchain/btx --source-commit "$(git rev-parse HEAD)" --build-with-guix --generate-snapshot --rollback <height or hash> --btx-cli ./build-btx/bin/btx-cli --rpc-arg=-datadir=<canonical-node-datadir> --attestations-dir <path-to-guix.sigs>/<version> --sign-with <release-gpg-key> --expected-signing-fingerprint <authorized-40-hex-fingerprint> --body-file doc/release-notes.md --token-file <github.key> --publish --bundle-dir /tmp/btx-release-bundle`
    - this command runs the same bundle collector and publisher used below, but it also stitches the Guix outputs, snapshot generation, attestation staging, and GitHub publish contract into one operator workflow
    - if you are staging from already-built outputs instead of building in place, pass `--guix-output-dir <guix-build-version/output>` and omit `--build-with-guix`
  - Native CLI preview path when you intentionally want a non-Guix release track:
    - `python3 scripts/release/cut_local_release.py --repo <staging-owner/repository> --tag <tag> --release-name <title> --source-repository <staging-owner/repository> --source-commit "$(git rev-parse HEAD)" --platform-spec "macos-arm64;<path-to-btxd>;<path-to-btx-cli>" --platform-spec "linux-arm64;<path-to-btxd>;<path-to-btx-cli>" --platform-spec "linux-x86_64;<path-to-btxd>;<path-to-btx-cli>" --bundle-dir /tmp/btx-native-cli-release --token-file <github.key> --smoke-platform macos-arm64 --publish`
    - use this only for clearly labeled native-built CLI releases; it does not claim Guix reproducibility or signer attestation coverage
    - if you do not also pass snapshot artifacts and a checksum signature, treat the output as a binary-install track rather than a full download-and-go release
  - Assemble the final fast-start bundle after the multi-architecture build finishes:
    - `python3 scripts/release/collect_release_assets.py --output-dir /tmp/btx-release-bundle --source <guix-output-dir>/x86_64-linux-gnu --source <guix-output-dir>/x86_64-linux-gnu-cuda12 --source <guix-output-dir>/aarch64-linux-gnu --source <guix-output-dir>/arm64-apple-darwin --snapshot /tmp/snapshot.dat --snapshot-manifest /tmp/snapshot.manifest.json --release-tag <tag> --release-name <title> --source-repository btxchain/btx --source-commit "$(git rev-parse HEAD)" --sign-with <release-gpg-key>`
    - this step must target a fresh output directory and produces the single directory that should be uploaded to the GitHub release page: binaries, snapshot, manifests, `SHA256SUMS`, and `SHA256SUMS.asc`
    - the collector now fails the staging step if any production-matrix archive is missing, so a successful run implies the generated `btx-release-manifest.json` contains one `platform_assets` entry for each required production archive
    - Linux publishes CPU-only and CUDA 12 x86_64 archives by default; see [`doc/linux-release-builds.md`](/doc/linux-release-builds.md) for the hardware and target-host driver matrix. CUDA 13, Windows, and macOS x86_64 archives may be staged as optional artifacts when built and tested.
    - if a `guix.sigs/<version>` directory is available, pass `--attestations-dir <path-to-guix.sigs>/<version>` so the final bundle also publishes signer-qualified attestation assets and records them in `attestation_assets`
  - Publish the bundle to GitHub Releases:
    - `python3 scripts/release/publish_github_release.py --repo btxchain/btx --tag <tag> --target-commit "$(git rev-parse HEAD)" --expected-signing-fingerprint <authorized-40-hex-fingerprint> --bundle-dir /tmp/btx-release-bundle --body-file <release-notes.md> --token-file <github.key> --publish`
    - the public publisher requires the manifest source repository and exact commit to match the target repository/tag commit, confirms that commit exists remotely, pins the authorized checksum-signing fingerprint, and refuses bundles whose on-disk assets drift from `SHA256SUMS`
  - Smoke-test the published bundle contract before announcing the release:
    - `python3 contrib/faststart/btx-agent-setup.py --release-manifest /tmp/btx-release-bundle/btx-release-manifest.json --asset-base-url /tmp/btx-release-bundle --platform linux-x86_64 --install-dir /tmp/btx-faststart-smoke --json`
    - this verifies that the local bundle is consumable by the same agent-facing installer path used after publication; published remote URLs additionally require `SHA256SUMS.asc` unless an operator explicitly opts out with `--allow-unsigned-release`
  - Run the BTX assumeutxo validation matrix before release publication:
    - `python3 test/util/generate_assumeutxo_test.py`
    - `python3 test/util/apply_assumeutxo_report_test.py`
    - `python3 test/util/release_bundle_manifest_test.py`
    - `python3 test/util/btx_agent_setup_test.py`
    - `python3 test/util/publish_github_release_test.py`
    - `python3 test/util/sign_release_bundle_test.py`
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
`contrib/faststart/README.md` as the active operator-facing docs, and treat
the Profile-1 ExactReplay golden corpus and seal section above as a BTX
release gate (it is not upstream Bitcoin Core material).

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
- [Linux release flavors](/contrib/guix/README.md#linux-release-flavors)
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

These examples assume `HEAD` is checked out at the exact release tag, so the
Guix work directory is `guix-build-${VERSION}`. If `HEAD` is not tagged, the
default work directory root is instead `guix-build-<short-commit-hash>` unless
`FORCE_VERSION` is exported explicitly.

In the `guix-build-${VERSION}/output/x86_64-apple-darwin` and `guix-build-${VERSION}/output/arm64-apple-darwin` directories:

    tar xf btx-${VERSION}-${ARCH}-apple-darwin-codesigning.tar.gz
    ./detached-sig-create.sh /path/to/codesign.p12 /path/to/AuthKey_foo.p8 uuid
    Enter the keychain password and authorize the signature
    signature-osx-${ARCH}.tar.gz will be created

### Windows codesigner only: Create detached Windows signatures

In the `guix-build-${VERSION}/output/x86_64-w64-mingw32` directory:

    tar xf btx-${VERSION}-win64-codesigning.tar.gz
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
for sig in signature-osx-*.tar.gz; do tar xf "${sig}"; done
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
