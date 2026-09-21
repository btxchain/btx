# BCP/1 / 0.34.8rc1 status (public-safe)

**Verdict: merge-ready as 0.34.8rc1.** Operator go-ahead is the remaining step to merge to main. Do not set `CLIENT_VERSION_IS_RELEASE` until the final 0.34.8 tag.

`CLIENT_VERSION` 0.34.8rc1 (`CLIENT_VERSION_RC=1`). `CLIENT_VERSION_IS_RELEASE` stays `"false"`. `automatic_spend_atoms` stays 0. No production `btxd` SIGKILL / `libexec` replace of a running inode.

This note does not name operator hosts. It does not claim a listing or a venue integration.

## BCP/1 (BTX Custody Profile 1)

Frozen monetary custody surface, independent of HCP / Model Network:

- Docs: `doc/integrations/exchange-custody.md`, `bcp1.md`, `external-sign.md`, `key-link.md`, `incident-recovery.md`, `README.md`
- Manifest: `contrib/bcp1/network-manifest.json`
- Wallet RPCs in `src/wallet/rpc/bcp1.cpp` (watch-only, external sign, deposit status, batch, consolidation)
- Live signer adapter: **command** (`-signer`). Software signer is regtest + `-bcp1software=1` only. PKCS#11 / KMIP / loopback HTTPS classes are fail-closed stubs (no client library linked) and are not wired to wallet RPC.
- ML-DSA-44 public-child derivation is `PUBLIC_CHILD_UNSUPPORTED`; watch-only uses `importdepositpool` / signer pubkeys
- Default wallet P2MR is the two-leaf tree `mr(pqhd(...), pk_slh(pqhd(...)))`; pool import uses `{pubkey, pubkey_slh}` and refuses a pubkey-only import that does not match a supplied address
- Deposit JSON: `-walletdepositnotify` (`%e` / `%j`); ZMQ topic names are unchanged
- Vectors: `src/test/data/bcp1-vectors/`
- Native: `src/wallet/test/bcp1_tests.cpp`
- Cert: `contrib/bcp1/run-certification.sh`, `test/functional/feature_bcp1.py`, `contrib/bcp1/Dockerfile` (`btx:exchange-local`, not published)

## Implementation vs certification

| Gate | Result |
|---|---|
| Native `test_btx --run_test=bcp1_tests` | **18/18 PASS** |
| Isolated-regtest `feature_bcp1.py` (`--timeout-factor=1`, ephemeral datadir) | **13/13 PASS** (prior workstream; mock signer remain fail-closed) |

`finalizeexternalsign` does not broadcast. There is no `deposit.finalized` event. Confirmation depth is PoW on the active chain; BCP/1 does not claim irreversibility.

## Still not a release

Do not flip `IS_RELEASE` on the final tag until asked. This RC may be tagged `v0.34.8-rc1`. PR 123 is ExactReplay public 0.34, not this tree. Vendor MPC / Key-Link attaching ML-DSA-44 is an open vendor question, not a BCP/1 PASS.
