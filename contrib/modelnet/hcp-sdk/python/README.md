# HCP/1 Python SDK

Typed HTTP client for the Hosted Control Plane (`btx_hcp.py`). **Not a wallet.**
It does not hold spend keys, call native wallet RPC, broadcast transactions, or
set `automatic_spend_atoms` to anything other than **0**. Unsigned example
envelopes confer no trust or settlement.

Contract: `src/modelnet/hcp/schemas/openapi.yaml`. Spec: `doc/modelnet/hcp/`.

## Decimal atom strings

Every `*_atoms` field is a canonical **unsigned decimal string** (`"1000"`,
never `1000` or `1000.0`). Do not parse amounts as IEEE floats. Conversion
quotes keep currency and exponent separate from BTX atoms.

```python
from btx_hcp import HcpClient

client = HcpClient("https://exchange.example/btx/hcp/v1", access_token=token, dpop=dpop)
# Amounts stay strings through create_intent / poll_operation.
```

## HTTP 202 is not settlement

HTTP **202** means accepted asynchronous work / UNKNOWN — **not** funded, signed,
or confirmed. The client returns the 202 body (or `{status: 202, unknown: True}`)
and **does not auto-submit** a finance mutation on 202, timeout, or lost
response. Poll `GET /operations/{id}` via `poll_operation`. Reuse the same
`client_operation_id`; never create a second intent to “retry.”

## body_id

```text
body_id = SHA384( UTF8("BTX/HCP/" + object_type + "/v1") || 0x00 ||
                  LE64(len(canonical_body)) || canonical_body )
```

```python
from btx_hcp import body_id, canonical_body
```

Vectors: `src/modelnet/hcp/examples/*.unsigned.json`.

```bash
python3 test_body_id.py
```

## Client (all 34 catalog operations)

| Method | Path |
|---|---|
| `get_profile()` | `GET /profile` |
| `search(q)` | `POST /capabilities/search` |
| `get_package(id)` | `GET /packages/{id}` |
| `get_economy(id)` | `GET /economy/{id}` |
| `create_handoff(...)` | `POST /handoffs` |
| `get_handoff(id)` | `GET /handoffs/{id}` |
| `enroll_device(...)` | `POST /devices/enroll` |
| `confirm_device(...)` | `POST /devices/{id}/confirm` |
| `revoke_device(id)` | `POST /devices/{id}/revoke` |
| `get_device_handoffs(id)` | `GET /devices/{id}/handoffs` |
| `report_readiness(...)` | `POST /devices/{id}/reports` |
| `get_balances()` | `GET /treasury/balances` |
| `create_funding_quote(body)` | `POST /finance/quotes` |
| `create_intent(body)` | `POST /finance/intents` |
| `get_finance_intent(id)` | `GET /finance/intents/{id}` |
| `authorize_finance_intent(id)` | `POST /finance/intents/{id}/authorize` |
| `submit_finance_intent(id)` | `POST /finance/intents/{id}/submit` |
| `cancel_finance_intent(id)` | `POST /finance/intents/{id}/cancel` |
| `get_finance_receipts(id)` | `GET /finance/intents/{id}/receipts` |
| `get_finance_receipt(id)` | `GET /finance/receipts/{id}` |
| `create_account_policy(body)` | `POST /policies` |
| `get_account_policy(id)` | `GET /policies/{id}` |
| `revoke_account_policy(id)` | `POST /policies/{id}/revoke` |
| `create_subscription(body)` | `POST /subscriptions` |
| `revoke_subscription(id)` | `POST /subscriptions/{id}/revoke` |
| `get_events()` | `GET /events` |
| `stream_events()` | `GET /events/stream` |
| `create_export(body)` | `POST /exports` |
| `get_export(id)` | `GET /exports/{id}` |
| `create_research_draft(body)` | `POST /research/drafts` |
| `validate_research_draft(id)` | `POST /research/drafts/{id}/validate` |
| `publish_research_draft(id)` | `POST /research/drafts/{id}/publish` |
| `get_research_submission(id)` | `GET /research/submissions/{id}` |
| `poll_operation(id)` / `get_operation(id)` | `GET /operations/{id}` |

Optional `Authorization: Bearer` and `DPoP`. Demo fixtures are not production
credentials. Native signing and submit stay outside this SDK (`automatic_spend_atoms=0`).
`OPERATIONS` in `btx_hcp.py` is the frozen 34-op catalog.
