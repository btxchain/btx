# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Cognitive Reserve v1.1 TypeScript SDK.

Additive HCP/1 extension (50 ops, 18 V1_1 types). Not a wallet.
HTTP 202 is UNKNOWN; never auto-submit. automatic_spend_atoms stays 0.
No /rpc passthrough. Default origin is HTTPS; loopback http://127.0.0.1
is REGTEST lab only via an explicit labOrigin flag.

```bash
node --test src/body_id.test.ts
```
