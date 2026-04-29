BTX Bridge Operator Helpers
===========================

This directory contains optional operator helpers for bridge recovery and
triage.

## `recover-pending-batch.sh`

Wraps the wallet-managed pending-bridge import flow for historical stuck
batches that were created before the recovery journal existed.

What it does:

1. optionally checks `gettxout` for the funded outpoint
2. calls `bridge_importpending`
3. defaults to `recover_now=true`
4. lets the wallet auto-generate a refund destination if one is not supplied
5. prints the import result and current `bridge_listpending` view for the
   specified outpoint

Example:

```bash
bash contrib/bridge/recover-pending-batch.sh \
  --wallet mywallet \
  --plan-hex "<plan_hex>" \
  --funding-txid "<funding_txid>" \
  --vout 0 \
  --amount 5.00010000
```

Run `bash contrib/bridge/recover-pending-batch.sh --help` for all options.
