# BTX Browser Wallet and Node Wallet Interop

BTX supports two wallet portability formats with different security goals:

- `.btxwallet` wallet bundle: a plaintext JSON recovery file used to move a
  BTX browser wallet into a native `btxd` descriptor wallet, or to export a
  single-seed native descriptor wallet for browser custody.
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

If you need the manual fallback path advertised by the browser wallet, create a
blank descriptor wallet and pass the bundle's public descriptors plus its
`pq_master_seed` to `importdescriptors`:

```bash
btx-cli createwallet "webwallet" false true "" false true

btx-cli -rpcwallet="webwallet" importdescriptors \
  '[{"desc":"<receive descriptor>","timestamp":<birthday>,"active":true,"range":[0,100]},
    {"desc":"<change descriptor>","timestamp":<birthday>,"active":true,"internal":true,"range":[0,100]}]' \
  '[]' \
  '["<pq_master_seed hex>"]'
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

Use `exportwalletbundle` only when you intentionally need a browser-compatible
plaintext `.btxwallet` export:

```bash
btx-cli -rpcwallet="mywallet" \
  exportwalletbundle "/secure/offline/mywallet.btxwallet.json"
```

For encrypted wallets, either unlock the wallet first or pass the optional
wallet passphrase argument:

```bash
btx-cli -rpcwallet="mywallet" \
  exportwalletbundle "/secure/offline/mywallet.btxwallet.json" "wallet passphrase"
```

The export contains the PQ master seed in plaintext plus public receive/change
descriptors. It can spend funds. Prefer `backupwalletbundlearchive` for normal
native backups and use `exportwalletbundle` only for deliberate browser/node
interop or recovery handoff.

## WebAssembly Signing Core

The `src/libbitcoinpqc/wasm` target builds the same ML-DSA-44 and
SLH-DSA-SHAKE-128s signing core for browser and Node use. CI checks that
caller-supplied entropy produces byte-identical key material in native and WASM
builds. Website releases should consume the generated `btx-pqc.js`,
`btx-pqc.mjs`, and `btx-pqc.wasm` artifacts rather than reimplementing PQ key
generation.
