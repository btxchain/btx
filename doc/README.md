BTX Node
========

Current BTX architecture/readiness source of truth
--------------------------------------------------
Use these docs first when you need the live post-`61000` hardening status,
security closeout, or future-upgrade boundary:

- [BTX Security Documentation](security/README.md)
- [BTX Post-Launch Optimization Roadmap](btx-postlaunch-optimization-roadmap.md)
- [BTX MatMul Product-Digest Mining Fix](btx-matmul-product-digest-mining-fix-2026-04-03.md)

Use these March 2026 docs as baseline launch references and historical
comparison points, not as the authoritative post-`61000` architecture summary:

- [BTX Shielded Production Status](btx-shielded-production-status-2026-03-20.md)
- [BTX SMILE v2 Genesis-Reset Readiness Tracker](btx-smile-v2-genesis-readiness-tracker-2026-03-20.md)
- [BTX SMILE v2 Transaction-Family Transition](btx-smile-v2-transaction-family-transition-2026-03-23.md)
- [BTX SMILE v2 Future-Proofed Settlement TDD](btx-smile-v2-future-proofed-settlement-tdd-2026-03-23.md)
- [BTX SMILE v2 Post-Launch Optimization Tracker](btx-smile-v2-optimization-tracker-2026-03-21.md)

Operator security and custody docs
----------------------------------
Use these docs first when you need the live BTX wallet, multisig, backup, or
key-management operating model:

- [BTX Key Management Guide](btx-key-management-guide.md)
- [Managing Wallets](managing-wallets.md)
- [BTX PQ Multisig Tutorial](btx-pq-multisig-tutorial.md)
- [BTX Shielded Pool Guide](btx-shielded-pool-guide.md)
- [Support for signing transactions outside of BTX](external-signer.md)

Operator bootstrap and release docs
-----------------------------------
Use these docs first when you need the live binary-install, fast-start, mining,
service-profile, or release-publication workflow:

- [BTX Download-and-Go Guide](btx-download-and-go.md)
- [Assumeutxo Usage](assumeutxo.md)
- [BTX GitHub Release Automation](btx-github-release-automation.md)
- [Release Process](release-process.md)
- [Mining Operator Helpers](../contrib/mining/README.md)
- [Fast-Start Validating Node Helpers](../contrib/faststart/README.md)

The release automation docs above now cover both the one-command local release
cut (`scripts/release/cut_release.py`) and the self-hosted GitHub Actions
workflow used to stage or publish major-architecture bundles. They also cover
the native subset release path (`scripts/release/cut_local_release.py`) for
CLI-only macOS/Linux publishing when Guix artifacts are not yet available.

Historical BTX analysis notes
-----------------------------
Many BTX-specific March 2026 design/audit docs are intentionally preserved as
historical records. When a document is historical, the file now says so at the
top and points back to the current source-of-truth docs above.

Setup
---------------------
BTX Node is the reference client for the BTX blockchain (MatMul AI-native Proof-of-Work). It supports the normal validating-node workflow as well as the fast-start validating-node path that boots from a published snapshot, so operators can download a binary and become useful immediately instead of waiting for a full historical sync.

Running
---------------------
The following are some helpful notes on how to run BTX Node on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/btx-qt` (GUI) or
- `bin/btxd` (headless)

### Windows

Unpack the files into a directory, and then run btx-qt.exe.

### macOS

Drag BTX Node to your applications folder, and then run BTX Node.

### Need Help?

* Start with the operator docs above if you are bootstrapping, mining, or publishing a release bundle.
* Use the fast-start guides for binary install, snapshot load, and `getchainstates` monitoring.
* Use the issue tracker or project-maintained support channels for repo-specific problems.

Building
---------------------
The following are developer notes on how to build BTX Node on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [BTX CUDA MatMul Optimization Notes](btx-cuda-matmul-optimization-notes-2026-04-13.md)
- [Windows Build Notes](build-windows-msvc.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)

Development
---------------------
This repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://doxygen.bitcoincore.org/)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

### Resources
* Discuss project-specific development in the repo issue tracker and adjacent maintainer channels used for BTX release and operator work.

### Miscellaneous
- [BTX Shielded Production Status](btx-shielded-production-status-2026-03-20.md)
- [BTX SMILE v2 Genesis-Reset Readiness Tracker](btx-smile-v2-genesis-readiness-tracker-2026-03-20.md)
- [BTX SMILE v2 Future-Proofed Settlement TDD](btx-smile-v2-future-proofed-settlement-tdd-2026-03-23.md)
- [BTX SMILE v2 Transaction-Family Transition](btx-smile-v2-transaction-family-transition-2026-03-23.md)
- [BTX SMILE v2 Optimization Tracker](btx-smile-v2-optimization-tracker-2026-03-21.md)
- [BTX Security Documentation](security/README.md)
- [BTX Post-Launch Optimization Roadmap](btx-postlaunch-optimization-roadmap.md)
- [BTX SMILE v2 Account Registry Redesign (Historical)](btx-smile-v2-shielded-account-registry-redesign-2026-03-22.md)
- [BTX Shielded Block Capacity, Bridge, and L2 Implementation Handoff (Historical)](btx-shielded-block-capacity-analysis-2026-03-14.md)
- [BTX PQC Script Profile](btx-pqc-spec.md)
- [BTX Key Management Guide](btx-key-management-guide.md)
- [BTX Public Archival Bootstrap](btx-public-node-bootstrap.md)
- [BTX PQ Multisig Specification](btx-pq-multisig-spec.md)
- [BTX PQ Multisig Tutorial](btx-pq-multisig-tutorial.md)
- [BTX PQ Multisig Implementation Tracker](pq-multisig-full-implementation-tracker.md)
- [Assets Attribution](assets-attribution.md)
- [btx.conf Configuration File](btx-conf.md)
- [CJDNS Support](cjdns.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [Managing Wallets](managing-wallets.md)
- [Multisig Tutorial (Legacy Bitcoin descriptors)](multisig-tutorial.md)
- [Offline Signing Tutorial](offline-signing-tutorial.md)
- [P2P bad ports definition and list](p2p-bad-ports.md)
- [PSBT support](psbt.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Transaction Relay Policy](policy/README.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
