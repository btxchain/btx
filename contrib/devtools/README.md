Contents
========
This directory contains tools for developers working on this repository.

deterministic-fuzz-coverage
===========================

A tool to check for non-determinism in fuzz coverage. To get the help, run:

```
RUST_BACKTRACE=1 cargo run --manifest-path ./contrib/devtools/deterministic-fuzz-coverage/Cargo.toml -- --help
```

To execute the tool, compilation has to be done with the build options
`-DCMAKE_C_COMPILER='clang' -DCMAKE_CXX_COMPILER='clang++'
-DBUILD_FOR_FUZZING=ON -DCMAKE_CXX_FLAGS='-fPIC -fprofile-instr-generate
-fcoverage-mapping'`. Both llvm-profdata and llvm-cov must be installed. Also,
the qa-assets repository must have been cloned. Finally, a fuzz target has to
be picked before running the tool:

```
RUST_BACKTRACE=1 cargo run --manifest-path ./contrib/devtools/deterministic-fuzz-coverage/Cargo.toml -- $PWD/build_dir $PWD/qa-assets/corpora-dir fuzz_target_name
```

clang-format-diff.py
===================

A script to format unified git diffs according to [.clang-format](../../src/.clang-format).

Requires `clang-format`, installed e.g. via `brew install clang-format` on macOS,
or `sudo apt install clang-format` on Debian/Ubuntu.

For instance, to format the last commit with 0 lines of context,
the script should be called from the git root folder as follows.

```
git diff -U0 HEAD~1.. | ./contrib/devtools/clang-format-diff.py -p1 -i -v
```

copyright\_header.py
====================

Provides utilities for managing copyright headers of `The Bitcoin Core
developers` in repository source files. It has three subcommands:

```
$ ./copyright_header.py report <base_directory> [verbose]
$ ./copyright_header.py update <base_directory>
$ ./copyright_header.py insert <file>
```
Running these subcommands without arguments displays a usage string.

copyright\_header.py report \<base\_directory\> [verbose]
---------------------------------------------------------

Produces a report of all copyright header notices found inside the source files
of a repository. Useful to quickly visualize the state of the headers.
Specifying `verbose` will list the full filenames of files of each category.

copyright\_header.py update \<base\_directory\> [verbose]
---------------------------------------------------------
Updates all the copyright headers of `The Bitcoin Core developers` which were
changed in a year more recent than is listed. For example:
```
// Copyright (c) <firstYear>-<lastYear> The Bitcoin Core developers
```
will be updated to:
```
// Copyright (c) <firstYear>-<lastModifiedYear> The Bitcoin Core developers
```
where `<lastModifiedYear>` is obtained from the `git log` history.

This subcommand also handles copyright headers that have only a single year. In
those cases:
```
// Copyright (c) <year> The Bitcoin Core developers
```
will be updated to:
```
// Copyright (c) <year>-<lastModifiedYear> The Bitcoin Core developers
```
where the update is appropriate.

copyright\_header.py insert \<file\>
------------------------------------
Inserts a copyright header for `The Bitcoin Core developers` at the top of the
file in either Python or C++ style as determined by the file extension. If the
file is a Python file and it has  `#!` starting the first line, the header is
inserted in the line below it.

The copyright dates will be set to be `<year_introduced>-<current_year>` where
`<year_introduced>` is according to the `git log` history. If
`<year_introduced>` is equal to `<current_year>`, it will be set as a single
year rather than two hyphenated years.

If the file already has a copyright for `The Bitcoin Core developers`, the
script will exit.

gen-manpages.py
===============

A small script to automatically create manpages in ../../doc/man by running the release binaries with the -help option.
This requires help2man which can be found at: https://www.gnu.org/software/help2man/

This script assumes a build directory named `build` as suggested by example build documentation.
To use it with a different build directory, set `BUILDDIR`.
For example:

```bash
BUILDDIR=$PWD/my-build-dir contrib/devtools/gen-manpages.py
```

headerssync-params.py
=====================

A script to generate optimal parameters for the headerssync module (src/headerssync.cpp). It takes no command-line
options, as all its configuration is set at the top of the file. It runs many times faster inside PyPy. Invocation:

```bash
pypy3 contrib/devtools/headerssync-params.py
```

gen-btx-node-conf.sh
====================

Generates a btx.conf file in `share/examples/` by parsing the output from `btxd --help`. This script is run during the
release process to include a btx.conf with the release binaries and can also be run by users to generate a file locally.
When generating a file as part of the release process, make sure to commit the changes after running the script.

For node operators, `gen-btx-node-conf.sh` also supports profile-based config generation:
- `./contrib/devtools/gen-btx-node-conf.sh fast` — newcomer/miner-first mode (prune=4096)
- `./contrib/devtools/gen-btx-node-conf.sh archival` — canonical/seed operators (prune=0)

This script assumes a build directory named `build` as suggested by example build documentation.
To use it with a different build directory, set `BUILDDIR`.
For example:

```bash
BUILDDIR=$PWD/my-build-dir contrib/devtools/gen-btx-node-conf.sh
```

build-btx-windows.ps1
=====================

PowerShell bootstrap for native Windows 11 BTX builds. It installs or validates
the Windows prerequisites, bootstraps a short-path standalone `vcpkg`, builds a
wallet-enabled headless BTX node, and runs a regtest smoke test.

Example usage:

```powershell
powershell -ExecutionPolicy Bypass -File .\contrib\devtools\build-btx-windows.ps1 -InstallDependencies
```

See [../../doc/build-windows-msvc.md](../../doc/build-windows-msvc.md) for the
full dependency list and the clone-to-mining walkthrough.

generate_assumeutxo.py
======================

Generate BTX assumeutxo metadata from a trusted synced node by calling
`dumptxoutset`, hashing the resulting snapshot file, and printing a ready-to-use
`m_assumeutxo_data` snippet.

Example usage:

```bash
python3 contrib/devtools/generate_assumeutxo.py \
  --btx-cli ./build-btx/bin/btx-cli \
  --chain main \
  --snapshot /tmp/mainnet-utxo-55000.dat \
  --snapshot-type rollback \
  --rollback 55000 \
  --rpc-arg=-datadir=/path/to/mainnet/node \
  --rpc-arg=-rpcport=19334 \
  --json-out /tmp/mainnet-utxo-55000.json
```

Use this output to:

1. update `src/kernel/chainparams.cpp`
2. publish the snapshot file alongside release binaries
3. include the snapshot SHA256 in release notes

Release Bundle Helpers
======================

The CI-covered release bundling and GitHub publication helpers live under
`scripts/release/`.

Assemble a fast-start release bundle from prebuilt archives plus the matching
snapshot assets, and generate the final `SHA256SUMS` / optional
`SHA256SUMS.asc`:

```bash
python3 scripts/release/collect_release_assets.py \
  --output-dir /tmp/btx-release-bundle \
  --source /tmp/guix-build/output/x86_64-linux-gnu \
  --source /tmp/guix-build/output/aarch64-linux-gnu \
  --source /tmp/guix-build/output/x86_64-w64-mingw32 \
  --source /tmp/guix-build/output/x86_64-apple-darwin \
  --source /tmp/guix-build/output/arm64-apple-darwin \
  --snapshot /tmp/snapshot.dat \
  --snapshot-manifest /tmp/snapshot.manifest.json \
  --release-tag v29.2-btx1 \
  --release-name "BTX v29.2-btx1" \
  --sign-with release-signing-key
```

The resulting `btx-release-manifest.json` includes `platform_assets` entries
for the primary Linux, macOS, and Windows archives. That is the stable contract
consumed by `contrib/faststart/btx-agent-setup.py` when an operator wants to
download the correct archive and bootstrap immediately from a published release.

Create or update a GitHub release and upload every file from the prepared
bundle directory using the token stored in `github.key`:

```bash
python3 scripts/release/publish_github_release.py \
  --repo btxchain/btx-node \
  --tag v29.2-btx1 \
  --bundle-dir /tmp/btx-release-bundle \
  --body-file /tmp/release-notes.md \
  --token-file /path/to/github.key \
  --publish
```

You can smoke-test the finished bundle locally before publishing:

```bash
python3 contrib/faststart/btx-agent-setup.py \
  --release-manifest /tmp/btx-release-bundle/btx-release-manifest.json \
  --asset-base-url /tmp/btx-release-bundle \
  --platform linux-x86_64 \
  --install-dir /tmp/btx-faststart-smoke \
  --json
```

If you want to apply the generated report back into `chainparams.cpp` without
editing the file by hand, use:

```bash
python3 scripts/apply_assumeutxo_report.py \
  --report /tmp/mainnet-utxo-55000.json \
  --chainparams src/kernel/chainparams.cpp
```

The helper accepts the full report emitted via `--json-out` and will refuse to
replace a non-empty `m_assumeutxo_data` block unless `--allow-non-empty` is
passed explicitly.

security-check.py
=================

Perform basic security checks on a series of executables.

symbol-check.py
===============

A script to check that release executables only contain
certain symbols and are only linked against allowed libraries.

For Linux this means checking for allowed gcc, glibc and libstdc++ version symbols.
This makes sure they are still compatible with the minimum supported distribution versions.

For macOS and Windows we check that the executables are only linked against libraries we allow.

Example usage:

    find ../path/to/executables -type f -executable | xargs python3 contrib/devtools/symbol-check.py

If no errors occur the return value will be 0 and the output will be empty.

If there are any errors the return value will be 1 and output like this will be printed:

    .../64/test_btx: symbol memcpy from unsupported version GLIBC_2.14
    .../64/test_btx: symbol __fdelt_chk from unsupported version GLIBC_2.15
    .../64/test_btx: symbol std::out_of_range::~out_of_range() from unsupported version GLIBCXX_3.4.15
    .../64/test_btx: symbol _ZNSt8__detail15_List_nod from unsupported version GLIBCXX_3.4.15

circular-dependencies.py
========================

Run this script from the root of the source tree (`src/`) to find circular dependencies in the source code.
This looks only at which files include other files, treating the `.cpp` and `.h` file as one unit.

Example usage:

    cd .../src
    ../contrib/devtools/circular-dependencies.py {*,*/*,*/*/*}.{h,cpp}
