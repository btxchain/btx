# Managing the Wallet

Note: BTX operational runbooks usually set explicit `-datadir` / `-conf` paths
(for example `/var/lib/btx` or `~/.btx/bitcoin.conf`). Default directory paths
below apply when those options are not provided.

For BTX-native P2MR custody, PQ multisig, timelocked recovery, external-signer
verification, shielded viewing-key separation, and AI-safe operating rules, see
the [BTX Key Management Guide](btx-key-management-guide.md). This document
remains the wallet-lifecycle reference for backup, restore, encryption, and
migration behavior.

## 1. Backing Up and Restoring The Wallet

### 1.1 Creating the Wallet

Since version 0.21, BTX no longer has a default wallet.
Wallets can be created with the `createwallet` RPC or with the `Create wallet` GUI menu item.

In the GUI, the `Create a new wallet` button is displayed on the main screen when there is no wallet loaded. Alternatively, there is the option `File` ->`Create wallet`.

The following command, for example, creates a descriptor wallet. More information about this command may be found by running `btx-cli help createwallet`.

```
$ btx-cli createwallet "wallet-01"
```

By default, wallets are created in the `wallets` folder of the data directory, which varies by operating system, as shown below. The user can change the default by using the `-datadir` or `-walletdir` initialization parameters.

| Operating System | Default wallet directory                                    |
| -----------------|:------------------------------------------------------------|
| Linux            | `/home/<user>/.bitcoin/wallets`                             |
| Windows          | `C:\Users\<user>\AppData\Local\Bitcoin\wallets`             |
| macOS            | `/Users/<user>/Library/Application Support/Bitcoin/wallets` |

### 1.2 Encrypting the Wallet

The `wallet.dat` file is not encrypted by default and is, therefore, vulnerable if an attacker gains access to the device where the wallet or the backups are stored.

Wallet encryption may prevent unauthorized access. However, this significantly increases the risk of losing coins due to forgotten passphrases. There is no way to recover a passphrase. This tradeoff should be well thought out by the user.

Wallet encryption may also not protect against more sophisticated attacks. An attacker can, for example, obtain the password by installing a keylogger on the user's machine.

After encrypting the wallet or changing the passphrase, a new backup needs to be created immediately. The reason is that the keypool is flushed and a new HD seed is generated after encryption. Any bitcoins received by the new seed cannot be recovered from the previous backups.

The wallet's private key may be encrypted with the following command:

```
$ btx-cli -rpcwallet="wallet-01" encryptwallet "passphrase"
```

Once encrypted, the passphrase can be changed with the `walletpassphrasechange` command.

```
$ btx-cli -rpcwallet="wallet-01" walletpassphrasechange "oldpassphrase" "newpassphrase"
```

The argument passed to `-rpcwallet` is the name of the wallet to be encrypted.

Only the wallet's private key is encrypted. All other wallet information, such as transactions, is still visible.

The wallet's private key can also be encrypted in the `createwallet` command via the `passphrase` argument:

```
$ btx-cli -named createwallet wallet_name="wallet-01" passphrase="passphrase"
```

Note that if the passphrase is lost, all the coins in the wallet will also be lost forever.

### 1.3 Unlocking the Wallet

If the wallet is encrypted and the user tries any operation related to private keys, such as sending bitcoins, an error message will be displayed.

```
$ btx-cli -rpcwallet="wallet-01" sendtoaddress "btx1qexampleaddress0000000000000000000000000" 0.01
error code: -13
error message:
Error: Please enter the wallet passphrase with walletpassphrase first.
```

To unlock the wallet and allow it to run these operations, the `walletpassphrase` RPC is required.

This command takes the passphrase and an argument called `timeout`, which specifies the time in seconds that the wallet decryption key is stored in memory. After this period expires, the user needs to execute this RPC again.

```
$ btx-cli -rpcwallet="wallet-01" walletpassphrase "passphrase" 120
```

In the GUI, there is no specific menu item to unlock the wallet. When the user sends bitcoins, the passphrase will be prompted automatically.

### 1.4 Backing Up the Wallet

To backup the wallet, the `backupwallet` RPC or the `Backup Wallet` GUI menu item must be used to ensure the file is in a safe state when the copy is made.

In the RPC, the destination parameter must include the name of the file. Otherwise, the command will return an error message like "Error: Wallet backup failed!" for descriptor wallets. If it is a legacy wallet, it will be copied and a file will be created with the default file name `wallet.dat`.

```
$ btx-cli -rpcwallet="wallet-01" backupwallet /home/node01/Backups/backup-01.dat
```

In the GUI, the wallet is selected in the `Wallet` drop-down list in the upper right corner. If this list is not present, the wallet can be loaded in `File` ->`Open Wallet` if necessary. Then, the backup can be done in `File` -> `Backup Wallet…`.

This backup file can be stored on one or multiple offline devices, which must be reliable enough to work in an emergency and be malware free. Backup files can be regularly tested to avoid problems in the future.

If the computer has malware, it can compromise the wallet when recovering the backup file. One way to minimize this is to not connect the backup to an online device.

If both the wallet and all backups are lost for any reason, the bitcoins related to this wallet will become permanently inaccessible.

### 1.4.1 BTX Wallet Backup Bundle RPC

BTX now provides a native per-wallet RPC for consistent backup exports:

- `backupwalletbundle` writes a new bundle directory for the selected wallet
- it captures the `backupwallet` file, descriptor exports, shielded viewing-key exports when permitted, `getbalances` + `z_gettotalbalance` snapshots, integrity metadata, and a manifest
- after the post-61000 privacy fork, omitted `include_viewing_keys` defaults to `false`
- if the wallet is encrypted and locked, `btx-cli -stdinwalletpassphrase` can prompt for the passphrase without echo and relock the wallet after export

Example:

```
$ btx-cli -rpcwallet=mywallet -stdinwalletpassphrase \
    backupwalletbundle /var/backups/btx/mywallet-bundle
```

This is the preferred single-wallet backup flow because it is implemented in BTX itself and exercises the same RPC surface used for restore verification.

### 1.4.2 BTX Wallet Bundle Archive RPC

BTX also provides a native encrypted single-file archive flow:

- `backupwalletbundlearchive` writes one passphrase-encrypted `.bundle.btx` file for the selected wallet
- it contains the same `backupwallet` file, descriptor exports, shielded viewing-key exports when permitted, `getbalances` + `z_gettotalbalance` snapshots, integrity metadata, and manifest captured by `backupwalletbundle`
- `restorewalletbundlearchive` restores that archive directly back into a wallet
- `btx-cli -stdinwalletpassphrase` can supply the wallet unlock passphrase without echo
- `btx-cli -stdinbundlepassphrase` can supply the archive encryption or restore passphrase without echo

Example:

```
$ btx-cli -rpcwallet=mywallet \
    -stdinwalletpassphrase \
    -stdinbundlepassphrase \
    backupwalletbundlearchive /var/backups/btx/mywallet.bundle.btx

$ btx-cli -stdinbundlepassphrase \
    restorewalletbundlearchive restored-wallet /var/backups/btx/mywallet.bundle.btx
```

This is the preferred sealed-offline backup flow when operators want a single encrypted file per wallet without relying on external archive tooling.

### 1.4.3 BTX Secure Backup Utility

BTX ships a helper script for the production backup flow that:

- loads wallets temporarily if needed
- prompts for wallet passphrases only when private exports require unlock
- runs `z_verifywalletintegrity` before export
- writes `backupwallet` snapshots, descriptor exports, `getbalances` + `z_gettotalbalance` snapshots, integrity metadata, and a manifest
- records `loadwallet`, archive, and integrity warnings in `export_warnings.log`, and includes per-wallet `integrity_ok` / `integrity_warnings` summary fields in the top-level manifest
- when `--encrypt-output` is used, stages only a short-lived backup snapshot in scratch space and writes the final archive atomically
- exports raw shielded viewing keys only when the active privacy regime still permits them and `--skip-viewing-keys` is not set
- optionally writes native encrypted `.bundle.btx` archives for each wallet

Example:

```
$ scripts/wallet_secure_backup.py \
    --cli build-btx/bin/btx-cli \
    --datadir /var/lib/btx \
    --output-dir /var/backups/btx \
    --encrypt-output
```

With `--encrypt-output`, the wrapper keeps the timestamped top-level export tree for metadata and index files, but writes each wallet itself as a native encrypted archive instead of a plaintext wallet bundle directory. In this mode the script preserves the native RPC default for `include_viewing_keys`, so post-61000 exports stay metadata-only unless you explicitly request otherwise through the RPC surface. `--remove-plaintext` remains accepted as a compatibility no-op because there are no plaintext per-wallet bundle directories in this mode.

If the target datadir is on `testnet`, `testnet4`, `signet`, or `regtest`, add the corresponding base CLI flag with `--cli-arg`, for example `--cli-arg=-regtest`.

### 1.5 Backup Frequency

The original Bitcoin Core wallet was a collection of unrelated private keys. If a non-HD wallet had received funds to an address and then was restored from a backup made before the address was generated, then any funds sent to that address would have been lost because there was no deterministic mechanism to derive the address again.

Bitcoin Core [version 0.13](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.13.0.md) introduced HD wallets with deterministic key derivation. With HD wallets, users no longer lose funds when restoring old backups because all addresses are derived from the HD wallet seed.

This means that a single backup is enough to recover the coins at any time. It is still recommended to make regular backups (once a week) or after a significant number of new transactions to maintain the metadata, such as labels. Metadata cannot be retrieved from a blockchain rescan, so if the backup is too old, the metadata will be lost forever.

Wallets created before version 0.13 are not HD and must be backed up every 100 keys used since the previous backup, or even more often to maintain the metadata.

### 1.6 Restoring the Wallet From a Backup

To restore a wallet, the `restorewallet` RPC or the `Restore Wallet` GUI menu item (`File` -> `Restore Wallet…`) must be used.

```
$ btx-cli restorewallet "restored-wallet" /home/node01/Backups/backup-01.dat
```

After that, `getwalletinfo` can be used to check if the wallet has been fully restored.

```
$ btx-cli -rpcwallet="restored-wallet" getwalletinfo
```

The restored wallet can also be loaded in the GUI via `File` ->`Open wallet`.

## Wallet Passphrase

Understanding wallet security is crucial for safely storing your Bitcoin. A key aspect is the wallet passphrase, used for encryption. Let's explore its nuances, role, encryption process, and limitations.

- **Not the Seed:**
The wallet passphrase and the seed are two separate components in wallet security. The seed, or HD seed, functions as a master key for deriving private and public keys in a hierarchical deterministic (HD) wallet. In contrast, the passphrase serves as an additional layer of security specifically designed to secure the private keys within the wallet. The passphrase serves as a safeguard, demanding an additional layer of authentication to access funds in the wallet.

- **Protection Against Unauthorized Access:**
The passphrase serves as a protective measure, securing your funds in situations where an unauthorized user gains access to your unlocked computer or device while your wallet application is active. Without the passphrase, they would be unable to access your wallet's funds or execute transactions. However, it's essential to be aware that someone with access can potentially compromise the security of your passphrase by installing a keylogger.

- **Doesn't Encrypt Metadata or Public Keys:**
It's important to note that the passphrase primarily secures the private keys and access to funds within the wallet. It does not encrypt metadata associated with transactions or public keys. Information about your transaction history and the public keys involved may still be visible.

- **Risk of Fund Loss if Forgotten or Lost:**
If the wallet passphrase is too complex and is subsequently forgotten or lost, there is a risk of losing access to the funds permanently. A forgotten passphrase will result in the inability to unlock the wallet and access the funds.

## Migrating Legacy Wallets to Descriptor Wallets

Legacy wallets (traditional non-descriptor wallets) can be migrated to become Descriptor wallets
through the use of the `migratewallet` RPC. Migrated wallets will have all of their addresses and private keys added to
a newly created Descriptor wallet that has the same name as the original wallet. Because Descriptor
wallets do not support having private keys and watch-only scripts, there may be up to two
additional wallets created after migration. In addition to a descriptor wallet of the same name,
there may also be a wallet named `<name>_watchonly` and `<name>_solvables`. `<name>_watchonly`
contains all of the watchonly scripts. `<name>_solvables` contains any scripts which the wallet
knows but is not watching the corresponding P2(W)SH scripts.

Migrated wallets will also generate new addresses differently. While the same BIP 32 seed will be
used, the BIP 44, 49, 84, and 86 standard derivation paths will be used. After migrating, a new
backup of the wallet(s) will need to be created.

Given that there is an extremely large number of possible configurations for the scripts that
Legacy wallets can know about, be watching for, and be able to sign for, `migratewallet` only
makes a best effort attempt to capture all of these things into Descriptor wallets. There may be
unforeseen configurations which result in some scripts being excluded. If a migration fails
unexpectedly or otherwise misses any scripts, please create an issue on GitHub. A backup of the
original wallet can be found in the wallet directory with the name `<name>-<timestamp>.legacy.bak`.

The backup can be restored using the methods discussed in the
[Restoring the Wallet From a Backup](#16-restoring-the-wallet-from-a-backup) section.
