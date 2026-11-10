# Recovering payments after restoring an encrypted backup

A restored encrypted descriptor wallet can initially omit payments to addresses
used after the backup was made. While locked, its post-quantum keys cannot extend
the backup's cached address range. Unlocking can derive more addresses, but does
not by itself revisit the blocks already processed during restoration.

This is incomplete wallet discovery, not evidence that the coins were destroyed.
The restore warning is conservative: it does not mean every restored wallet is
missing payments.

## Explicit recovery

Use the restored wallet's own RPC endpoint throughout:

1. Unlock it using the existing wallet passphrase operation or Qt unlock dialog.
2. Call `keypoolrefill` while unlocked. RPC `walletpassphrase` already attempts a
   refill; the explicit step also covers Qt unlock, which does not. If the
   default range is insufficient, choose a finite `newsize` from the number of
   addresses known to have been used since the backup. This size is the number
   of keys ahead of the wallet's current address index, not an absolute index.
3. Call `rescanblockchain` to scan from height zero through the current tip.
   Only use a later start height if you independently know it includes every
   missing receipt and the wallet permits that range. Wallets with shielded
   state have additional historical-scan restrictions.
4. Check the scan result and expected receipts and balance, then relock the
   wallet when finished.

`getwalletinfo` reports scan progress and `abortrescan` requests cancellation.
A failed, aborted or unavailable-history scan is not completed recovery. The
existing passphrase-protected scan can defer timeout relocking until it finishes;
explicit locking and passphrase changes during that scan are refused. These
instructions do not change that behavior.

A pruned node cannot rescan blocks it no longer has. In-progress background
validation can also make history unavailable. Follow the scan's error instead of
treating an incomplete balance as final. Recovery requires the relevant history
and a derived address range covering the actual usage; one refill does not
promise discovery of arbitrarily distant addresses.

This guidance concerns loaded encrypted descriptor-wallet backup restoration.
It does not change encryption, key retention, derivation, scanning, consensus or
normal unlock behavior. No automatic rescan is performed.
