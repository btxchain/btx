# Free-first policy

Normative: root addendum §5 (D03). Not CSV PASS.

v1.1 D03: retrieval is **free-first, reciprocal-first, market-second**.
Automatic spending is off unless the operator opts into a finite budget.

## Modes

| Mode | Price | Authorization |
|---|---|---|
| `FREE_ONLY` | Zero-price only; wait/retry if incomplete | Fresh-install default. No wallet. |
| `FREE_FIRST_APPROVAL` | Free work continues; paid alternative is a separate confirmation | Exact quote, fee, exposure |
| `FREE_FIRST_BUDGET` | Automate only inside a durable budget | Explicit opt-in |
| `EXPLICIT_PAID` | User picks a paid provider | Exact price/fee; PQ and ACL still apply |

`FREE_ONLY` **never** flips to paid because a deadline expires.
`FREE_FIRST_APPROVAL` cannot treat a stalled free session as consent.

A denied or cryptographically invalid free host is never “better” merely
because its quote is zero.

## Planner (normative intent)

Filter for exact content, PQ1, ACLs, admission, and resource ceilings.
Compare eligible supply. Estimate completion from **bottleneck ranges**,
not aggregate bandwidth. Unknown ETA is not infinite willingness to pay.

Hybrid retrieval (when paid exists) buys only missing or deadline-critical
ranges. This tree’s `getmodel` paid modes return `APPROVAL_REQUIRED` and
do not spend.

## State machine

```
URI_ACCEPTED -> POLICY_CHECKED -> MANIFEST_VERIFIED
 -> FREE_DISCOVERY -> FREE_ACTIVE -> VERIFIED_LOCAL
                         |
                         +-> WAIT_FREE / CANCEL   (FREE_ONLY, no source)
Any crypto failure        -> REJECT_SOURCE, never downgrade TLS
VERIFIED_LOCAL            -> demand-seed (default) within storage/bandwidth
                             or local-only if seed=off
```

Give-back ratio is a local convenience target, not a debt. No demand means
no artificial traffic to meet a ratio. Metered links, disk pressure, and
monetary validation load can pause sharing.
