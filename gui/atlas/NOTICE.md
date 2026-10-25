# Provenance and licensing

The authored Atlas source is supplied under the MIT license in LICENSE.
No Neuron Explorer implementation, stylesheet, screenshot, shader or font was
copied. Its general scientific visualization concepts informed the design.
OpenUI and Octopus supplied conceptual patterns; their runtimes are not bundled.
The icon SVG and native icon conversions are independently authored.

References (not runtime dependencies):
- https://github.com/lyramakesmusic/neuron-explorer
- https://github.com/wandb/openui
- https://github.com/miuuyy/Octopus-SI-OS

Actual native dependencies are pinned directly in Cargo.toml. Transitive dependency
licenses/versions and source checksum closure require a resolved and audited
Cargo.lock and generated notices before distribution. The native WebView and OS
components remain external dependencies. No font files or private credentials are
included. Do not reuse this NOTICE as a completed third-party SBOM.

Authoritative BTX source pin:
https://github.com/btxchain/btx/tree/18ea826ee3d82edf65a274c00316bd118ed731d2

Inspected baseline references: src/qt/bitcoingui.h, src/qt/modelnetpage.h,
src/qt/optionsmodel.h, src/qt/pairingpage.cpp, src/consensus/amount.h,
doc/modelnet/rpc.md and doc/modelnet/generate.md. This is a partial inspected
inventory, not a claim that all 7,506 PR files were reviewed.

Technical primary references for integration:
- https://v2.tauri.app/security/capabilities/
- https://v2.tauri.app/security/csp/
- https://v2.tauri.app/plugin/deep-linking/
- https://v2.tauri.app/plugin/autostart/
- https://docs.rs/arboard/3.6.1/arboard/struct.Clipboard.html
