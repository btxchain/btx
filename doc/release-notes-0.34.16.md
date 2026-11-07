0.34.16
=======

This tag packages the current review branches as a node release. The 0.35
line stays open for ModelNet work that is not in these branches yet.

Included
--------

- `btx-035/swarm` through `d522af52`, including the wallet, Windows, jail,
  and ML-KEM review fixes.
- `btx-035/atlas-native` through `afe27a2b`, the desktop candidate.
  The Linux archive ships `btx-atlas`. Running it needs WebKitGTK 4.1 and GTK 3
  (`libwebkit2gtk-4.1-0` and `libgtk-3-0`). Qt stays; Atlas is the additional desktop.
- `btx-035/model-security-v2` through `6fd4564e`, the local security guard.
  `btx-security` is the offline administrative CLI. On a running node the same
  guard is `btx-cli modelsecurity`.

Linux x86_64 binaries in the archive: `btxd`, `btx-cli`, `btx-tx`, `btx-wallet`,
`btx-util`, `btx-qt`, `btx-atlas`, `btx-security`, `btx-guardd`, the model
helpers, and `btx-native-qualify`. Windows, macOS, arm64, and CUDA archives
are not attached: this build has no Windows cross compiler, no macOS SDK, no
aarch64 compiler, and no CUDA toolkit.

Upgrading from 0.34.15
----------------------

Stop the node with `btx-cli stop`, wait for `btxd` to exit, and back up the
data directory. Unpack the whole archive and run `bin/btxd` from it: the files
in `bin/` start `libexec/*.real` with the bundled `lib/`, so a `bin/btxd`
copied on its own exits with "packaged binary is missing". `btxd` and
`btx-cli` need glibc 2.38 or newer (Ubuntu 24.04, Debian 13). No `btx.conf`
option was removed.

- A node that syncs from genesis still stops at block 126,978: block 126,979
  fails the unshield velocity cap (#272). This release does not change that.
- `-modelbind` (TCP 29447) now defaults to off with `-listen=0`, `-proxy`, an
  `-onlynet` without ipv4 or ipv6, or a `-bind` on loopback only. An explicit
  `-modelbind` still wins. 0.34.15 opens 29447 with those settings.
- Model peers are also found on the local network over UDP 29448
  (`-modellandiscovery`, default 1 when the model helper listens and neither
  `-proxy` nor `-connect` is set). The socket binds all interfaces when the
  host has an up, multicast-capable RFC1918 interface. Hints never enter the
  monetary AddrMan. `-modellandiscovery=0` turns it off.
- `btxd` runs `btx-guardd --stdio` as a child process. It opens no port and
  keeps its state in `<modeldir>/security`. The Linux archive ships it as
  `libexec/btx-guardd`, beside `libexec/btxd.real`. While the guard is not
  running, `modelsecurity` returns `SEC_GUARD_NOT_READY` and the node keeps
  running.
- `-autoupdate` now defaults to 0 when `-proxy` is set or `-onlynet` excludes
  ipv4 and ipv6. Otherwise it stays 1 on mainnet.
- `signrawtransactionwithwallet` and `walletprocesspsbt` take
  `adjust_timelocks` (default `false`). For a selected csv, cltv or refund
  leaf, 0.34.15 rewrote nLockTime, nSequence and version while signing. This
  release refuses and names the required value unless `adjust_timelocks` is
  true.
- A parked deep reorg has its own entry in `warnings`, and `warnings` and
  `-alertnotify` follow the latest deep-reorg alarm, not only the first one.
- `-modelnet=0` turns off the model helper, both model ports and `btx-guardd`.

Further notes for this release: `doc/release-notes-253.md` (macOS ML-DSA
wallet cache), `doc/release-notes-358.md` (lightwatch) and
`doc/release-notes-htlc-presign.md` (presigned HTLC claims).

Not included
------------

Validation, fork choice, issuance, script rules, MatMul acceptance, and the
signer set are unchanged. The height-100 candidate and the `legacy_lt_*`
results are not in this tag. `automatic_spend_atoms` stays `"0"`. Qt stays.

Local model servers
-------------------

This node does not embed llama.cpp or Ollama, and it has no quantize RPC.
A GGUF tensor whose declared size runs past the file, overflows, or overlaps
the next tensor is rejected before it is accepted. Generation runs only when
the operator points `BTX_LLAMA_CLI` or `BTX_MODEL_GENERATE` at a local
program. `-modelbind` is the PQ1 peer port, not an unauthenticated upload or
inference API. Do not publish a separate llama.cpp or Ollama server from
this host without authentication in front of it.
