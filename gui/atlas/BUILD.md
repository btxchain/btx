# Build and packaging

## Dependency and compiler prerequisites

The source pins Rust 1.95.0 and direct crate versions. The frontend has no npm
runtime dependencies or compilation step. Node 22 runs the unit tests. A native
build needs the platform SDK and the native WebView dependencies required by the
pinned Tauri version. These are external dependencies, not eliminated by using a
framework-free frontend.

**Cargo.lock is intentionally not fabricated.** No Rust toolchain or package
registry access existed in the authoring environment. On a controlled build host:

```sh
cd gui/atlas
rustup toolchain install 1.95.0 --profile minimal --component rustfmt --component clippy
cargo generate-lockfile
cargo metadata --locked --format-version 1 > dependency-metadata.json
cargo tree --locked > dependency-tree.txt
# Review licenses, advisories, checksums and exact versions; commit Cargo.lock.
# rust-ini stays at 0.21.1. 0.21.3 adds ParseOption fields that
# tauri-plugin-deep-link 2.6.2 does not set, so the host does not compile.
cargo fmt --all
cargo test --locked -p btx-atlas-core
cargo check --locked -p btx-atlas
cargo clippy --locked --workspace --all-targets
cargo build --locked --release -p btx-atlas
```

Formatting and compiler diagnostics must be resolved before review. Do not replace
native failures with a JavaScript stub or remove a safety check to make a test pass.
The integration-test/example crate uses the explicit `atlas_core` library name.

On Linux install WebKitGTK 4.1/GTK/AppIndicator build dependencies. Windows needs
the supported MSVC toolchain/SDK and WebView2; macOS needs Xcode command-line tools.
The included native workflow is a starting build matrix; it has not been run.

To build through CMake after committing the lock:

```sh
cmake -S gui/atlas -B build-atlas
cmake --build build-atlas
```

This standalone target does not change BTX's existing `BUILD_GUI` or compile the
node. Build `btxd`, `btx-modeld` and required helpers using the repository's native
instructions and the exact candidate source.

## Native run

```sh
cd gui/atlas
cargo run --locked -p btx-atlas
```

Enter a literal loopback RPC endpoint with the actual node RPC port. Select its
`.cookie` using the native picker. Confirm the exact chain and genesis. No
credential is put into browser preferences, JavaScript configuration or model
context. Select the correct network's cookie. Cookie rotation is read per call.

A trusted `btxd` executable may be selected and launched by the user. It is not
shipped in this ZIP, and the launcher does not independently establish its signing
trust. Native node/helper packaging remains an integration gate. Atlas never
kills the node simply because the GUI closes.

## Installers and signing

Use a reviewed/pinned Tauri CLI compatible with the locked crate release, and
run its native bundle build from the `src-tauri` app. Original icons and desktop
protocol configuration are included. The CLI is a development dependency, not a
runtime JS framework. Configure owner-held signing/notarization credentials in
CI secrets; no signing identity or secret is included here.

Validate Windows/MSIX or NSIS/MSI choices, macOS application/DMG notarization,
Linux AppImage/deb/rpm packaging, license notices and offline WebView deployment.
Do not call a raw `cargo build` a signed or reproducible installer. Automatic
updates are intentionally absent until signed-update, rollback and downgrade
policy are implemented and independently reviewed.

## Preview and ordinary browser tests

```sh
python3 contrib/atlas/preview.py
node --test gui/atlas/tests/core.test.mjs
node gui/atlas/tests/static-audit.mjs
python3 contrib/atlas/model_check.py
python3 gui/atlas/tests/browser_smoke.py --out browser-report.json
```

The browser harness needs separately installed Playwright/Chromium. It does not
alter browser security policy. The authoring environment blocked URL navigation;
its executed smoke used a documented offline test-only module transform instead.
Run the ordinary-origin test to qualify real ES modules, workers and CSP.

## Native disposable regtest

After building the exact BTX node, CLI and the locked Rust app:

```sh
python3 contrib/atlas/qualify_regtest.py \
  --repo . --btxd /absolute/path/to/btxd --cli /absolute/path/to/btx-cli \
  --out native-wallet-report.json --accept-disposable-regtest
```

The script creates a new temporary datadir and a generated qualification wallet,
refuses mainnet, mines through the native regtest path, and exercises Atlas core
transaction construction/signing/broadcast and duplicate denial. Mining failures
remain failures; do not disable MatMul or alter consensus to get a green result.
This is not a UI-dialog, external signer, reorg, wallet recovery or all-platform test.
