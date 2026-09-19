# HCP/1 TypeScript SDK

Fetch client for the Hosted Control Plane (`src/index.ts`). **Not a wallet.**
Browser and agent code must not possess custody-signing keys, call native wallet
RPC, or broadcast spends. `automatic_spend_atoms` remains **0**; this package
never increments it. There is no `/rpc` passthrough.

Contract: `src/modelnet/hcp/schemas/openapi.yaml` and
`src/modelnet/hcp/schemas/rpc-catalog.json` (34 REST operations). Spec:
`doc/modelnet/hcp/`.

## Decimal atom strings

Keep every `*_atoms` field as a canonical **unsigned decimal string**
(`"1000"`). Do not coerce to `number` (IEEE float). `createFinanceIntent` /
`createIntent` take JSON objects so amounts stay decimal text through
`JSON.stringify`. Conversion quotes identify currency and exponent separately
from BTX atoms.

```ts
import { HcpClient } from "./src/index.ts";

const client = new HcpClient("https://exchange.example/btx/hcp/v1", accessToken, dpop);
await client.createFinanceIntent({
  client_operation_id: "op-demo-fund-01",
  quote_id: "quote-demo",
  expected_quote_id: "218705dd2e377b731b199b9bb12dbe337538baf70edd5a1f4ae20e92f2c046a877d94043b10b95b0f9d0538707e1ff15",
});
await client.createFundingQuote({
  action: "FUND_RELEASE",
  principal_atoms: "1000",
  max_network_fee_atoms: "30",
});
```

## HTTP 202 is not settlement

HTTP **202** means accepted asynchronous work / UNKNOWN — **not** native
settlement. The client returns the parsed 202 body (or
`{ status: 202, unknown: true }` when empty) and **does not auto-submit**
authorize / submit / cancel on 202, timeout, or a lost response. Call
`getOperation(id)` (`GET /operations/{id}`). Reuse the same
`client_operation_id`; never mint a second intent to recover from 202.

Timeouts throw `HcpError("UNKNOWN", "timeout")` and do not retry a finance
mutation.

## body_id

```text
body_id = SHA384( UTF8("BTX/HCP/" + object_type + "/v1") || 0x00 ||
                  LE64(len(canonical_body)) || canonical_body )
```

`canonical_body` is UTF-8 compact JSON with lexicographically sorted object
keys (Python `json.dumps(..., sort_keys=True, separators=(",", ":"),
ensure_ascii=False)`).

```ts
import { bodyId, canonicalBody } from "./src/index.ts";
```

Vectors: `src/modelnet/hcp/examples/*.unsigned.json`.

```bash
node --test src/body_id.test.ts
```

## Not a wallet

`HcpClient` is an HTTP wrapper over the 34 catalog operations. Envelope
`body_id` is the domain-separated SHA-384 over canonical body bytes
(`BTX/HCP/{object_type}/v1`). Unsigned examples under
`src/modelnet/hcp/examples/*.unsigned.json` are schema/codec vectors only.
This client does not sign ML-DSA statements or native transactions
(`automatic_spend_atoms=0`). `getPackage` returns raw bytes; `streamEvents`
returns an SSE `ReadableStream` and does not JSON-parse it.

| Method | Path |
|---|---|
| `getProfile()` | `GET /profile` |
| `search(q)` | `POST /capabilities/search` |
| `getPackage(packageCoreId)` | `GET /packages/{package_core_id}` |
| `getEconomy(targetId)` | `GET /economy/{target_id}` |
| `createHandoff(...)` | `POST /handoffs` |
| `getHandoff(handoffId)` | `GET /handoffs/{handoff_id}` |
| `enrollDevice(body)` | `POST /devices/enroll` |
| `confirmDevice(deviceId, body)` | `POST /devices/{device_id}/confirm` |
| `revokeDevice(deviceId)` | `POST /devices/{device_id}/revoke` |
| `getDeviceHandoffs(deviceId)` | `GET /devices/{device_id}/handoffs` |
| `reportReadiness(deviceId, body)` | `POST /devices/{device_id}/reports` |
| `getBalances()` | `GET /treasury/balances` |
| `createFundingQuote(body)` | `POST /finance/quotes` |
| `createFinanceIntent(body)` | `POST /finance/intents` |
| `getFinanceIntent(intentId)` | `GET /finance/intents/{intent_id}` |
| `authorizeFinanceIntent(intentId, body)` | `POST /finance/intents/{intent_id}/authorize` |
| `submitFinanceIntent(intentId, body)` | `POST /finance/intents/{intent_id}/submit` |
| `cancelFinanceIntent(intentId, body)` | `POST /finance/intents/{intent_id}/cancel` |
| `getFinanceReceipts(intentId)` | `GET /finance/intents/{intent_id}/receipts` |
| `getFinanceReceipt(receiptId)` | `GET /finance/receipts/{receipt_id}` |
| `createAccountPolicy(body)` | `POST /policies` |
| `getAccountPolicy(policyId)` | `GET /policies/{policy_id}` |
| `revokeAccountPolicy(policyId)` | `POST /policies/{policy_id}/revoke` |
| `createSubscription(body)` | `POST /subscriptions` |
| `revokeSubscription(subscriptionId)` | `POST /subscriptions/{subscription_id}/revoke` |
| `getEvents(query?)` | `GET /events` |
| `streamEvents()` | `GET /events/stream` |
| `createExport(body)` | `POST /exports` |
| `getExport(exportId)` | `GET /exports/{export_id}` |
| `createResearchDraft(body)` | `POST /research/drafts` |
| `validateResearchDraft(draftId)` | `POST /research/drafts/{draft_id}/validate` |
| `publishResearchDraft(draftId, body)` | `POST /research/drafts/{draft_id}/publish` |
| `getResearchSubmission(submissionId)` | `GET /research/submissions/{submission_id}` |
| `getOperation(operationId)` | `GET /operations/{operation_id}` |

Aliases: `createIntent` → `createFinanceIntent`; `pollOperation` → `getOperation`.
Optional `Authorization: Bearer` and `DPoP`. Mutations that declare
`Idempotency-Key` in OpenAPI take it as a trailing string argument. Native
signing and submit stay outside this SDK (`automatic_spend_atoms=0`).
