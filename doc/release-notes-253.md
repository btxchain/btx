Wallet
------

- Descriptor wallets written by the macOS `btxd` of a v0.34.x release can hold
  cached ML-DSA-44 public keys that their seed does not derive. Such a wallet
  created without a passphrase failed every load with "Wallet corrupted", and
  `btxd` exited if it was set to load at startup. One encrypted after creation
  returned an error from `walletpassphrase` and stayed unlocked. The first now
  loads, also at startup, and the second unlocks and relocks as usual. Such a
  wallet keeps the cached keys, logs a warning, and signs through the SLH-DSA
  leaf. (#253)
- Once this version has loaded such a wallet, and unlocked it if it is
  encrypted, v0.34.15 opens it too, because the one-time descriptor cache
  upgrade is then recorded as done. The seed still does not restore the
  cached ML-DSA keys, and spends from such a wallet still pay about 0.39x the
  requested fee rate. Keep the wallet file and move the coins to a new wallet
  made by this version.
