# Security assurance: what is and is not established

## Threat model

The intended adversary can control peer/model metadata, model output, imported
surface/workflow/capture content, untrusted URLs and network timing. They must not
obtain wallet authority or transform observation into permission. The trusted
computing base includes the selected local BTX node, OS, desktop app code,
WebView/Tauri/Rust dependencies, trusted local model execution adapter and native
confirmation UI. Same-user malware, compromised administrator/kernel, malicious
node binary, hostile graphics driver and physical key theft are not solved here.

## Implemented controls (native implementation not yet executed)

| Boundary | Control | Remaining evidence |
|---|---|---|
| Untrusted content → UI | textContent, strict bounded JSON, no HTML/JS/eval | Fuzzing and actual native CSP/WebView attack tests |
| Model → authority | fixed seven read tools, redaction, no parameters from the model for writes | Real hostile local-model evaluation |
| UI → node | packaged-main-window IPC allowlist, native cookie, loopback-only socket | Native iframe/origin/redirect tests on three platforms |
| Mutation → effect | frozen request, expiring single-use approval, OS dialog, chain recheck | Native race/dialog/timeout fault injection |
| Payment → signing | exact atoms, script/change/fee/input checks, frozen transaction skeleton | Real native regtest, PQ address, encrypted and external signer tests |
| State → recovery | durable intent, unknown latch, no automatic retry | Crash/restart and disk-full tests |
| Files → native | user OS selection, size/type constraints, conflict hashes, no overwrite exports | Windows ACL/reparse-point and cross-platform atomicity audit |
| Dependencies → release | exact direct versions and locked-build gate | Resolve/audit/commit Cargo.lock; SBOM and advisory review |

## Honest limitations

`#![forbid(unsafe_code)]` applies to authored Rust modules, not all dependencies,
WebViews, operating systems or graphics drivers. Memory-safe source structure is
not proof of a vulnerability-free application. Native code has not been compiled
in this authoring environment, so compiler errors and platform API mismatches may
remain. Do not ship until the native matrix and adverse-path tests pass.

The abstract model checker enumerates a finite approval machine. It is not linked
by a machine-checked refinement proof to the real Rust functions, IPC races or
node semantics. JavaScript property loops and static checks are tests, not general
formal proofs. Performance measurements do not establish worst-case execution
time, bounded total RSS, GPU-driver correctness or cross-platform behavior.

The hash-chained journal detects accidental inconsistency but is not authenticated
against a same-user attacker who can rewrite the entire file. Sensitive credentials
are zeroized in selected native buffers; serde values, WebView input controls and
OS dialogs may retain copies. Secret entry currently occurs in the trusted app
form before transfer to native memory, not in a hardened hardware input path.
Full native-secret-entry migration is a release-hardening item.

Unix cookie mode checks exist. Equivalent Windows owner/DACL enforcement is not
implemented and is a release blocker. The selected executable's byte hash is shown;
it is not a signature verification or defense against same-user TOCTOU/DLL attacks.
Ordinary local RPC is authenticated but not a multi-tenant OS sandbox boundary.

Read-only status can still be private. The assistant projection is deliberately
narrow, but user-visible raw operator inspectors and exports remain local/private.
Visual privacy masking does not sanitize every raw JSON inspector or export.
Never publish those outputs without a separate redaction review.

## Key adversarial acceptance cases

Attempt model-generated `sendrawtransaction`; forged native confirmation IDs;
request-body substitution; stale connection epoch; changed genesis; nested-frame
IPC; DNS rebinding; malformed/chunked HTTP; duplicate JSON keys; huge or recursive
surface documents; private-source widgets; prototype keys; poisoned model names;
raw private-key export; changed outputs after signing; duplicate broadcast after
lost response; reorg; wallet changed while a plan is open; full disk on audit write;
withdrawn grants; missing helper; unsupported model; malicious dependency/update.
Each case needs a result tied to the exact integrated source and platform.

## Release decision

A qualified replacement needs the acceptance manifest, immutable logs, a complete
Qt parity review, signed platform artifacts and independent review. Until then,
use only disposable regtest wallets and non-sensitive model data for native tests.
