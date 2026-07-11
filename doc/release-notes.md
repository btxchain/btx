BTX version 0.33.1 is being prepared for release from:

  <https://github.com/btxchain/btx/releases>

This point release adds the WebAssembly post-quantum signing target used by the
BTX browser wallet, makes the browser `.btxwallet` to native-node recovery path
first class, and keeps ZMQ notifications enabled in release binaries.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/btxchain/btx/issues>

To receive release and update notifications, please subscribe to:

  <https://btx.dev/>

# How to Upgrade

After the official v0.33.1 release is published, shut down the previous node
cleanly, wait for it to exit, and replace its `btxd`, `btx-cli`, and related
binaries with the signed final release artifacts. Back up wallets and
configuration before upgrading. Do not install unpublished candidate assets.

Version 0.33.1 introduces no new mainnet consensus activation and does not
change the P2MR transaction wire format.

# Compatibility

BTX is supported on Linux, macOS 13+, and Windows 10+. CUDA mining remains a
hardware-specific accelerated path with a CPU fallback.

# Notable Changes

## Browser wallet interop

- `src/libbitcoinpqc/wasm` now builds `btx-pqc.js` and `btx-pqc.wasm`, exposing
  ML-DSA-44 and SLH-DSA-SHAKE-128s keygen/sign/verify for browser, worker, and
  Node environments.
- The WASM build uses caller-supplied entropy only and disables filesystem and
  OS-random dependencies, matching the browser wallet custody model.
- CI builds the WASM module with Emscripten, runs sign/verify tests in Node, and
  compares native and WASM key-generation vectors from identical entropy.
- Native wallet RPCs provide the node-side recovery bridge for browser
  `.btxwallet` v1 JSON exports. `restorewalletbundle` creates a descriptor
  wallet from a browser bundle, while `importwalletbundle` imports the same
  verified seed/descriptors into an existing descriptor wallet.
- Browser bundle import verifies the format, version, network, coin type,
  account, seed length, first receive address, and optional descriptor strings
  before installing key material.
- `doc/btxwallet-browser-node-interop.md` documents the supported browser-to-node
  recovery flow and the security boundary between plaintext `.btxwallet` files
  and encrypted native `.bundle.btx` archives.

## Release binary ZMQ support

- Guix release builds now pass `-DWITH_ZMQ=ON`, so published `btxd` binaries
  support `-zmqpub*` notifications without requiring a source rebuild.

# Known Limitations

- `.btxwallet` files contain plaintext PQ master seed material. Handle them like
  private keys, keep them offline, and delete temporary copies after import.
- Native node wallets should be exported with `backupwalletbundlearchive`; the
  node intentionally does not provide a default encrypted-wallet-to-plaintext
  browser-seed export path.

# Credits

Thanks to the contributors and reviewers of the browser wallet, post-quantum
WASM, btxwallet import, release engineering, and ZMQ notification work that
prepared v0.33.1.
