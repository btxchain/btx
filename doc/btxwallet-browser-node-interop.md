# BTX Browser Wallet and Node Wallet Interop

BTX supports two wallet portability formats with different security goals:

- `.btxwallet` browser wallet export: a plaintext JSON recovery file produced by
  the BTX browser wallet for import into a native `btxd` descriptor wallet.
- `.bundle.btx` native archive: an encrypted node-wallet backup produced by
  `backupwalletbundlearchive` for offline/operator recovery.

Do not treat these formats as interchangeable. A `.btxwallet` file contains the
PQ master seed directly and must be handled like private-key material. A
`.bundle.btx` archive is the preferred native backup format when exporting from
`btxd`.

## Browser to Native Node

Use `restorewalletbundle` when the browser wallet exported a `.btxwallet` or
`.btxwallet.json` file and the destination should be a new native wallet:

```bash
btx-cli restorewalletbundle "webwallet" "/secure/offline/btx-wallet.btxwallet.json" null true
```

For an encrypted restored wallet, pass the optional fifth argument:

```bash
btx-cli restorewalletbundle \
  "webwallet" \
  "/secure/offline/btx-wallet.btxwallet.json" \
  null \
  true \
  "new native wallet passphrase"
```

Use `importwalletbundle` only when importing into an existing blank descriptor
wallet:

```bash
btx-cli -rpcwallet="webwallet" importwalletbundle "/secure/offline/btx-wallet.btxwallet.json" true
```

Both RPCs verify the bundle before installing keys:

- `format` must be `btx-wallet-bundle`
- `version` must be `1`
- `network` must match the active chain
- `coin_type`, when present, must match the active chain
- `account`, when present, must be `0`
- `pq_master_seed` must be 32 bytes encoded as 64 hex characters
- `first_receive_address`, when present, must derive from that seed
- `descriptors`, when present, must match the seed, network, account, and
  receive/change branches

## Native Node to Browser

Native node wallets should be exported with the native archive RPC:

```bash
btx-cli -rpcwallet="mywallet" \
  -stdinwalletpassphrase \
  -stdinbundlepassphrase \
  backupwalletbundlearchive /secure/offline/mywallet.bundle.btx
```

The node does not provide a default native-to-browser raw seed export. That is
intentional: exporting the node PQ master seed into a browser-importable
plaintext JSON file would bypass wallet encryption and produce a file that can
spend the wallet. If a recovery workflow requires browser custody, generate the
wallet in the browser first, then import the `.btxwallet` into the node with
`restorewalletbundle`.

## WebAssembly Signing Core

The `src/libbitcoinpqc/wasm` target builds the same ML-DSA-44 and
SLH-DSA-SHAKE-128s signing core for browser and Node use. CI checks that
caller-supplied entropy produces byte-identical key material in native and WASM
builds. Website releases should consume the generated `btx-pqc.js` and
`btx-pqc.wasm` artifacts rather than reimplementing PQ key generation.
