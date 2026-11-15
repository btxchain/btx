# macOS Qt deployment and combined package acceptance

**Fix: shipped SVG, PDF and virtual-keyboard plugins could not load because their Qt frameworks were missing.** Product commit: [f16b502ec28dc91cec236bc4fb2195709b045a16](https://github.com/sunnyriverr/btx/commit/f16b502ec28dc91cec236bc4fb2195709b045a16), based on `36ab43008cac48aa5c8410e4b70d90a249196a33`. The code and in-tree tests are byte-identical to native fixture `28196c4409f201ae9fedf0628ad466670dc1e072`; this publication does not imply a new test run.

## Repair and before/after

macdeployqt returned zero while printing unresolved-rpath errors. A first-pass library hint alone was insufficient. The repair makes staged plugins additional dependency roots in one bounded second pass, retains all plugins, removes temporary build-time rpaths, and rejects remaining errors. Existing dependency rewriting and ad-hoc signing remain in place. Original installed Qt and producer binaries are not edited.

On macOS 15.8.2 ARM64 with Qt 6.12, the same native QPluginLoader probe explicitly linked to bundled QtCore loaded Cocoa/style controls before and after. SVG/PDF/virtual-keyboard cases failed before and passed after (2/5 -> 5/5); no ambient Homebrew images were loaded. The final maintained packaging suite ran 30 tests: OK, one skip. See [deployment results](deployment.json) and [unit output](maintained-unit-suite.log).

Maintained regression entry point from the repository root: `python3 test/util/package_release_archive_test.py`. The native retained-binary recipe was executed through [run 42536199088](https://github.com/sunnyriverr/btx/actions/runs/42536199088), fixture `28196c4409f201ae9fedf0628ad466670dc1e072`, under `contrib/devtools/mac-resume/`. It restores exact prior CMake/Cargo outputs; it is not a clean full build. The [manifest](manifest.json) records byte identities and prerequisite build runs.

## Combined package acceptance and attribution

Separately assembled the same deployment fix with **Jpp-matata's #452 Mac guard sibling change**, from head `4a5a4db86bfb7d698f6cad788666e872d65e171e` (packager blob `88a876fed7531fca359660c9bed8d3299b17eaa7`). His code is not included in this PR and no result here qualifies #452's separate Linux Qt-major change. Original licenses and authorship are preserved. Integration patch identity and archive hash are in [combined results](combined.json).

- Stock archive admission passed; 86 Mach-O images passed ARM64/signature/absolute Homebrew dependency checks. Declared minimum-OS floors are at most 15.0; execution was on 15.8.2 only. All 20 shipped Qt plugins loaded in the native probe.
- The identical physical-path two-boot lifecycle case passes ordinary node/helper health without #452 but fails the guard contract; adding his Mac sibling change passes both boots, 20 health and 20 guard polls, persisted public identity, fresh process/guard boot identities, clean shutdown and runtime cleanup. No manual helper/guard startup qualified this result.
- Actual Atlas and Qt main windows rendered and were visually inspected: [Atlas](atlas-window.png) (NOT CONNECTED), [Qt](qt-window.png) (disposable regtest). Qt was launched through its shipped wrapper; Atlas was the raw shipped executable. Original producer binaries/caches and the working node were preserved.

Executed entry points: [archive/plugin/image run 42538530491](https://github.com/sunnyriverr/btx/actions/runs/42538530491), fixture `567f10683c25241c956d19bb0d17ac309ff6230d`; [physical lifecycle/Atlas run 42539622275](https://github.com/sunnyriverr/btx/actions/runs/42539622275), fixture `4839d8c3626483a5cd862bdd87dd18dc2e1ad0eb`; [Qt window run 42540231795](https://github.com/sunnyriverr/btx/actions/runs/42540231795), fixture `e6934321457f1836cf44360aab3c0c3f0d58c5b0`. Recipes reside at each fixture's `contrib/devtools/mac-resume/`; download prerequisites are pinned there. Hosted artifacts expire 22–23 November; key results and captures are retained in this branch.

## Interpretation and limits

The first lifecycle fixture used macOS's symlinked `/tmp`; the guard correctly refused that security path. A direct paired control returned exit 2 for the alias and READY/exit 0 for the physical `/private/tmp` path. Only the affected lifecycle stage was repeated with the physical path; no security rule or timeout was weakened. First Qt capture caught transient startup and was repeated only for a stable main window. Raw top-level node_started/app_launched defaults were stale: child lifecycle records and inspected captures support the qualified result, not those defaults.

No Atlas RPC connection, wallet/signing/spending, mining, GPU/ExactReplay, mainnet, throughput, full-suite, installer/URI/Launch Services/Finder, older-OS execution, Developer ID/notarization/Gatekeeper or release signoff. Optional-plugin loading failure is not a claim that the original main window always crashes. The standalone fix's native plugin proof is separate from combined acceptance requiring JPP's pending guard change.

Next decision: review the focused deployment repair and integrate it alongside the separately owned guard change if accepted. Review or adoption alone does not warrant more runs.
