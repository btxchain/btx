# BTX Atlas — native replacement application source candidate

A new standalone BTX desktop application, not a Qt WebView page. The interface is
framework-free ES modules, semantic DOM and a custom WebGL2/Canvas renderer. A
Rust/Tauri host owns node authentication, exact financial operations, native
confirmation, file access and the bounded local-model session. `btxd` remains the
monetary, ModelNet and swarm authority.

**Pinned parent:** `btxchain/btx` PR #245, `btx-035/swarm`,
`18ea826ee3d82edf65a274c00316bd118ed731d2`.
**Suggested descendant:** `btx-035/atlas-native`; PR target: `btx-035/swarm`.

## Read the qualification boundary first

This is substantive new source code with executed JavaScript tests and a scoped
browser smoke test. It is **not a verified, complete Qt replacement release**.
Rust/Cargo were unavailable in the authoring container, so the native code,
wallet flows, OS dialogs, installer configuration and native tests have **not
been compiled or executed here**. There is no resolved `Cargo.lock` yet. The
integrating agent must resolve and audit the dependency closure, compile and fix
native/platform issues, and pass the supplied parity and release gates before
retiring Qt. Missing desktop/localization/recovery details are recorded in
`FEATURE_PARITY.md`; they are not claimed complete.

The package does not claim end-to-end formal security, worst-case performance,
full accessibility conformance, native sandbox qualification or independently
verified distributed model execution. A small finite abstract approval model
was checked; that is not proof that the implementation refines that model.

## Implemented source

* Twelve workspaces: Atlas, Models, Swarms, Work, Research, Economy, Compute,
  Mining, Wallet, Activity, Tools and Settings. Contextual inspector, searchable
  lists, command palette, responsive layout, accessible table counterparts and
  a local-assistant drawer.
* Deterministic perspective/flat graph renderer, local layout worker, bounded
  typed arrays, generation checks, event-driven drawing and explicit disposal.
  GPU-visible data is bounded; larger source graphs are explicitly sampled.
* An exact money library in Rust and JavaScript; native transaction preparation,
  recipient/change/fee/input verification, unchanged-transaction checks after
  signing, separate sign/broadcast reviews and no automatic unknown-outcome retry.
* Wallet selection, balances, transaction pages, receive QR, coin selection and
  locking, address labels, PSBT import/inspection/sign/finalize workflows and
  administration templates. Templates are checked against the node's `help`;
  an unavailable method remains unavailable rather than simulated.
* **221 operation templates** and **59 node-configuration keys**. The 26 Qt
  model RPCs that had no template now have one, plus dedicated model panels.
  A template is not evidence of a tested replacement for every Qt interaction.
* Native-only loopback RPC authentication, strict bounded JSON, separate read
  allowlist, native immutable approvals, a durable redacted journal, selected-file
  configuration editing with conflict detection and explicit login-start control.
* A local-model bridge using the real `generatemodel` contract, limited sessions,
  bounded redacted observations, no wallet/shell/write tools, and no cloud fallback.
* Read-only validated generated surface documents, local revision history,
  workflow draft DAGs, evidence comparison and model-activation capture inspection.
  The optional manual SafeTensors capture script records real local Linear outputs;
  it is not bundled inference, a scientific qualification or a native data grant.
* Additive integration tool, CMake entry, CI definitions, native test sources,
  a disposable-regtest harness, Qt source scanner and a fail-closed release gate.

## First use

From the separately distributed source package, `python3 apply.py --repo /path/to/btx` performs a dry
run. Add `--apply` to create the descendant branch and copy the overlay. The
installer makes **no commit, push or PR**, changes no monetary source and deletes
no Qt source. Read `AGENT_HANDOFF.md` before integration.

A browser preview is available without Rust:

```sh
python3 ../../contrib/atlas/preview.py
```

Then open the printed loopback URL and choose the explicitly labelled demo.
Browser mode has **no RPC transport**, wallet writes or model execution. It is
not a browser-accessible financial gateway. Actual native mode requires a running
local BTX node, its RPC port and a cookie chosen in an OS dialog.

## Tests and reports

See the package `reports/` directory and `VALIDATION.md`. Reports distinguish
executed tests from supplied-but-unrun tests. Benchmarks are synthetic CPU
microbenchmarks on the recorded host, not GPU frame-rate or whole-app RSS claims.

## Non-goals of this change

No consensus rewrite, new swarm daemon, new model-admission bypass, forced
checkpoint replacement, new automatic-spending permission, cloud model service,
remote RPC dashboard, JavaScript evaluation of model output or key custody.
Qt is retained as a rollback path until the new app is qualified. It is not used
as a runtime dependency by this new application.
