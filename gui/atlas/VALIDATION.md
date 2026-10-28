# Validation record

## Executed in the authoring container

* Node 22 JavaScript unit/property tests: **67 passed**, zero failures. These
  include 20,000 exact money roundtrips, strict JSON and URI rejection, bounded
  caches/polling/traversal, generated-surface denial, DAG cycles, capture bounds
  and camera mathematics.
* Source-structure audit: **12 checks passed**. This is textual/static structure
  checking, not compilation, whole-program taint analysis or sandbox validation.
* Finite abstract model: **78 states / 228 transitions**; approval/intent/submit
  and no-retry invariants hold in that model only.
* Chromium 144 offline app smoke: twelve workspaces, assistant open/close,
  repeated navigation/listener cleanup, filtering, flat/perspective toggle, and
  desktop/compact screenshots. No page errors. Canvas2D path exercised.
* Synthetic CPU microbenchmarks: layout, traversal, exact arithmetic, capped LRU.
  Raw times and host metadata are in the accompanying JSON reports.

## Scope of the browser run

Browser policy in the environment blocked URL navigation. It was not disabled or
bypassed. The executed test loaded the authored assets into an offline page using
a test-only TypeScript-to-CommonJS transform. A local worker was disabled in that
harness, using the implementation's synchronous fallback. This does **not** verify
normal-origin ES modules, the real Worker path, the production CSP, WebGL2,
Tauri IPC or native desktop behavior. The ordinary-origin browser harness is
provided for those later checks. No synthetic topology was represented as a real
BTX network.

## Integration on parent 18ea826ee3d82edf65a274c00316bd118ed731d2

The overlay was applied unchanged onto that parent, then checked on Linux
x86_64 with Rust 1.95.0 and Node 24. Qt was not removed and Atlas was not made
the default client.

* JavaScript unit/property tests: **67 passed**, zero failures.
* Source-structure audit: **12 checks passed** after the monetary-node check
  was pointed at the Atlas tree. Inside a BTX checkout it now refuses a diff
  to `src/validation.cpp` and `src/wallet/wallet.cpp` instead of requiring
  those node files to be absent.
* Finite abstract model: **78 states / 228 transitions**, abstract model only.
* `cargo fmt --all --check` is clean. `Cargo.lock` was generated with the
  pinned toolchain and contains only crates.io sources.
* `btx-atlas-core` tests: **32 passed** (26 library, 6 contract), zero
  failures. Clippy on that crate is clean with `-D warnings`. One
  `map_or(true, ...)` became `is_none_or`, with the same result.
* Qt lexical inventory at this parent: 79 `QAction`s, 77 options, 21 `.ui`
  files, 55 direct RPC references. 26 of those methods have no Atlas
  template. 177 Atlas templates are not a direct Qt call. This is not parity.
* `cargo check --locked -p btx-atlas` passes, and the debug `btx-atlas`
  binary links, when the WebView development headers are available.
  `rust-ini` is locked at 0.21.1 because 0.21.3 does not compile with
  `tauri-plugin-deep-link` 2.6.2. Two unused imports in the host were
  removed. Clippy is clean for `btx-atlas` and `btx-atlas-core` with
  `-D warnings`. This is not an installer, a signed package, or a run
  against a live node. The Linux CI workflow installs
  `libwebkit2gtk-4.1-dev`, `libgtk-3-dev` and
  `libayatana-appindicator3-dev` before that check.
* Direct Qt calls with no Atlas template: `cacheencryptedmodel`,
  `ensurebtxcapability`, `getbountycapabilities`, `getbtxcapabilityevents`,
  `getbtxruntimecapabilities`, `getbtxttctrace`, `getcloudstorageinfo`,
  `getmodeldirectoryentry`, `getmodeleconomyentry`, `getmodeleventsequence`,
  `getmodelfeedsequence`, `getmodelprofile`, `getmodelreleaseeconomics`,
  `getresourcegovernorinfo`, `getsearchstatus`, `listmodelwatches`,
  `planbtxcapability`, `planbtxcapabilityupdate`, `prefetchbtxcapability`,
  `publishmodelsearchrecord`, `releasebtxcapability`, `searchcollections`,
  `searchpublishers`, `sleepbtxcapability`, `switchbtxcapability`,
  `wakebtxcapability`. A template is not a completed workflow.
* Those 26 names now have catalog templates (219 total) and Models panels.
  `getbtxcapabilityevents` is not a silent read: the handler drops stored
  events at or below the cursor, so Atlas opens native review instead.
  The catalog is now 221 templates. This is not Qt retirement.

## Controls added after that inventory

These controls exist. They are not qualification records.

* Close can hide the window, and the tray icon can be hidden, through
  `atlas_desktop`. Quit still leaves the node running. A missing tray does
  not block startup.
* Language catalogs ship English plus the Qt translation of the word Wallet
  where that source string already existed. Every other Atlas label stays
  English. Money and QR fonts are limited to generic families already on
  the machine.
* Hardware signing is `enumeratesigners` and `walletdisplayaddress` behind
  native review. No device was attached.
* The Windows CI job checks that the built executable is not writable by
  Everyone, Users, or Authenticated Users. The installer signature script
  returns NOT_RUN unless a Windows installer has a valid Authenticode
  signature. No certificate was used. Updater artifacts are off.
* Eight relay settings now use the conf names the node actually reads
  (`acceptnonstdtxn`, `acceptunknownwitness`, `spkreuse`,
  `permitbarepubkey`, `permitbaremultisig`, `permitbareanchor`,
  `permitbaredatacarrier`, `acceptnonstddatacarrier`). `spkreuse` is
  `allow` or `conflict`. A write still requires the existing config review.
  Defaults were not changed.
* `qualify_regtest.py` records the regtest, wallet, and address checks,
  then fails when the tip is below 101 and does not run the spend example.
  MatMul was not disabled. The script was not executed.
* Disposable regtest qualification was not run. The script mines 101 blocks,
  and regtest MatMul v4 starts at height 100. MatMul was not disabled to
  force a result. Windows, macOS, installers, hardware signing, local-model
  inference, native IPC/CSP, WebGL2 and Qt behavioral parity remain unproven.

## macOS observations on d2bfcd3f

A reviewer ran this head on Apple Silicon with Rust 1.95.0. Those results
are observations. They are not a qualification record from this tree, and
they do not cover Windows.

* Source checks matched the integration notes above: 67 JavaScript tests,
  12 static checks, and the 78/228 abstract model.
* `btx-atlas-core` tests passed (32). Clippy `-D warnings` was clean.
  `cargo build --locked --release -p btx-atlas` produced a binary. A
  loopback-only sandbox kept it up for 15 seconds. The window was not
  inspected on that run. Node on that machine was 24.15; the workflow
  pins 22.
* Default `qualify_regtest.py` stopped where this file predicted.
  `generatetoaddress 101` left the tip at height 99 and the node logged
  the ExactReplay defer at height 100. The example then reported
  insufficient funds. The script now fails at that short tip and includes
  the node log and the cargo example output. It still does not disable
  MatMul.
* A separate run used extra regtest options, including MatMul heights set
  past the mine and economic MatMul validation. That run is not the
  qualification script. With those options the reviewer connected Atlas
  to the local cookie, saw a masked balance, prepared an exact send,
  confirmed sign and broadcast in the native dialog, and observed one
  confirmation after another block. History showed raw Unix times, blank
  amount and address headers, and headers broken inside words. Those
  three display bugs are fixed here. The JavaScript suite is now 68 tests.
  `read_allowed` is one line so rustfmt 1.95 accepts it.
* Native confirmation stays on the main thread. The system dialog is
  meant to wait there until the operator answers.
* Models, the assistant, PSBT export, coin control, Playwright, installers,
  signing, local-model inference, and Windows were not part of that run.
  The 26 Qt method names above are still templates, not workflows.

## Not executed here

Rust compilation, Cargo dependency resolution, native unit/integration tests,
real BTX regtest, native wallet/PSBT approval, physical hardware signing, real
local-model inference/capture, Windows/macOS/Linux package runs, GPU frame timing,
whole-app RSS/startup/idle profiling, accessibility conformance, signed installer
or update tests, complete Qt behavioral equivalence and physical distributed
swarm/economy qualification. Native reports are explicitly NOT_RUN.

## Interpreting benchmarks

The layout benchmark indexes 1k/10k/100k synthetic entities. The renderer does not
attempt to draw 100k full interactive labels; it caps visible GPU objects at 10k.
A typed-array byte count is not total memory usage. The traversal benchmark builds
adjacency over the source graph before its visited-node bound. CPU timings on an
EPYC container do not predict a laptop's WebView or shared-GPU inference behavior.

## Re-run and record

Follow BUILD.md. Generate reports against the integrated Git SHA, OS, compiler,
WebView version, BTX binary digest and dependency lock. Preserve failed outcomes.
Do not change a NOT_RUN record to PASS because a test source file exists.
