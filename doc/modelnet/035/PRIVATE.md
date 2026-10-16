# BTX 0.35 private gates

Status: PRIVATE DEVELOPMENT / NOT RELEASE QUALIFIED. This document is not an announcement and not a production signature.

The monetary client version in this tree stays 0.34.15. The 0.35 work is an additional research plane on the private branch `private/btx-035/integration`.

## What the gates do

`lab035` dispatches all 75 `lab.*` methods. Identity creation keeps the secret in the process and does not return it. Signing produces a v1.1 envelope that verifies. Channel publication rejects a repeated sequence. Action permits are one-use, and a runtime pause blocks execute until resume. Admission without replay coverage fails closed, so hosting that decision is rejected. Unknown methods still return `BTX035_NOT_IMPLEMENTED`. Unknown request fields return `BTX035_SCHEMA`. `automatic_spend_atoms` stays `"0"`.

A strict model is served only when admission has two independent replay roots and full coverage. A quarantined id is not served. An unregistered legacy id stays servable so existing 0.34 call sites keep working. That choice is covered by `unregistered_legacy_id_stays_allowed`.

`contrib/modelnet/git-remote-btx` accepts a stock `git push`, `git clone`, and `git pull` after the whole update list is known. The ref journal still rejects a gap, a duplicate, an equivocation, and a rollback. The helper does not spend a wallet.

`contrib/modelnet/lab035_regtest_journey.py` starts four local regtest processes and two Git origins. Each process creates its own research identity. `getblockchaininfo` stays on regtest.

## Binaries

The private Linux Release build uses GCC 15, Qt 6, and ZeroMQ. The 2026-10-13 relink of `btxd`, `btx-qt`, `btx-cli`, `btx-tx`, `btx-util`, `btx-wallet`, and the model helper binaries is in `release-candidate/linux-x86_64/`. `btxd -version` prints v0.34.15. `btxd` links `libzmq`. `btx-qt` links Qt 6 Widgets, Gui, Network, DBus, Core, and ZeroMQ. Metal is a macOS framework, so the Linux `btx-matmul-backend-info` reports Metal compiled false.

The private macOS ARM64 Release build uses one compile job, Qt 6, ZeroMQ (static), and Metal. The 2026-10-13 one-core rebuild includes the lab API revision. `btxd -version` and `btx-qt -version` print v0.34.15. `btxd` links Metal. `btx-qt` links Qt 6 Widgets, Gui, Network, and Core, and both binaries contain the ZeroMQ notifier symbols. The macOS helper binaries other than `btxd`, `btx-qt`, `btx-cli`, `btx-tx`, `btx-util`, and `btx-wallet` were not relinked in this pass.

`PanelSnapshot` is still the read-only lab record. The desktop binary is `btx-qt`.

## Acceptance execution

Every acceptance case has an operator evidence row under the private `evidence/native/` directory. The operator table has no `NOT_RUN` row and no `BTX035_NOT_IMPLEMENTED` row: 570 cases passed a native suite that exercises that requirement, and 3 Windows cases are `BLOCKED` because this network has no Windows runner. Index rebuild, witnessed external actions, and package inventory authentication are covered by `modelnet_035_remaining_tests`. That suite rejects a cloud account, hides a private object that shares a public content hash, refuses success before an external witness checkpoint, and authenticates package bytes only after an operator pin matches the inventory digest. The release gate refuses completion while any mandatory row is not `PASS`, including the Windows `BLOCKED` rows, and it does not turn an old `NOT_RUN` row into a pass on recovery. The macOS `btxd` and `btx-qt` rebuilt on 2026-10-13 include this revision. Helper binaries other than the daemon, Qt client, and the cli tools were left as the previous build.

The sealed specification file `planning/acceptance.csv` still contains `NOT_RUN` in every row. Its package checker rejects any other value. That file is the contract's initial column, not the execution record.

Windows x86-64 has no runner on this network, so that platform is `BLOCKED`. The reference training path is a four-step fixture, not a production model. Status remains PRIVATE DEVELOPMENT / NOT RELEASE QUALIFIED.
