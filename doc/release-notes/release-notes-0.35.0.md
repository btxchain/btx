# BTX 0.35.0 release candidate

This branch reports `v0.35.0rc1` (`CLIENT_VERSION_MINOR` 35, `CLIENT_VERSION_BUILD` 0, `CLIENT_VERSION_RC` 1, `CLIENT_VERSION_IS_RELEASE` true). It is not the shipping tag `v0.35.0`. The last shipping tag remains **v0.34.15**. Notes for that tag stay in [release-notes-0.34.15.md](release-notes-0.34.15.md).

The candidate keeps the monetary node and adds the swarm as a thread inside `btxd` when Modelnet is compiled. `-modelnet` defaults on. `-modelnet=0` leaves the monetary node running. The thread does not spend. `automatic_spend_atoms` stays 0. `btxd` does not start `btx-swarmd` or `btx-paynetd`.

The public map of the candidate is [doc/modelnet/swarm/00_THIS_TREE.md](../modelnet/swarm/00_THIS_TREE.md). Product behavior and the work that remains are in [01_PRODUCT_AND_DEFAULT_LIFECYCLE.md](../modelnet/swarm/01_PRODUCT_AND_DEFAULT_LIFECYCLE.md) and [14_PERFORMANCE_SCALE_AND_ACCEPTANCE_METHODOLOGY.md](../modelnet/swarm/14_PERFORMANCE_SCALE_AND_ACCEPTANCE_METHODOLOGY.md).

This candidate is not release-qualified. A passing in-process suite is not a second host, a second GPU, Windows, macOS, or a sealed acceptance run.

The published 0.35.0rc1 file set does not yet include a CUDA Linux archive. v0.34.15 shipped `btx-0.34.15-x86_64-linux-gnu-cuda13.tar.gz`. A GPU consensus node that starts the rc1 Linux `btxd` without that CUDA build reports a CPU provider and can stall at the next MatMul block. A CUDA Linux archive has to ship with 0.35 before those operators can move.

## Published Linux archive

The published 0.35.0rc1 Linux `btxd` imports OpenSSL 3.2. The `lib/` directory in that archive supplies it. Ubuntu 24.04's OpenSSL 3.0 does not. Point only that `btxd` process at `lib/`. Do not put that directory on a library path for every program.

In that same published set, `btxd` was reported at the existing `GLIBC_2.38` floor. `btx-qt` and the bundled GnuTLS were reported to need `GLIBC_2.43`, so the GUI does not start on Ubuntu 24.04. A consensus-mode CPU node that stops at the first MatMul block is the ExactReplay rule, not a fault in that archive.

A 0.34.15 binary built without the model plane rejects `-modelnet=0` as an unknown parameter. Drop that flag when starting such a binary.

## Auto-update and -proxy

An auto-update check is a direct HTTPS connection from this host to the manifest origin (`https://btx.dev` by default). It does not use `-proxy`, `-onion` or `-onlynet`. On mainnet `-autoupdate` now defaults to 0 when `-proxy` is set or `-onlynet` excludes ipv4 and ipv6, the same tests that already turn off `-listen`, `-discover` and `-dnsseed` by default. `-onion` or `-listenonion` alone do not change the default, because ipv4 and ipv6 peers still connect directly. `-autoupdate=1` keeps it on, and the check still connects directly.

When auto-update is on, `btxd` logs one line at startup with the manifest URL, the interval, whether it installs a verified release (`-autoupdateseamless`), and that `-autoupdate=0` turns it off. When the rule above turns it off, `btxd` logs why.

The fetch helper now starts as `python3 -I` (isolated mode). It uses only the standard library, so the working directory, `PYTHON*` environment variables and the user site directory no longer reach its module path. An `-autoupdatepython` interpreter must accept `-I` (CPython 3.4 and later do).
