# Model economy

BTX 0.34.7 is not only model transport. Search, feed, and release
coordination let demand turn into capital formation for new open models.

```
PRIVATE MODEL
    ↓
ENCRYPT + PRESEED
    ↓
SEARCHABLE RELEASE CAMPAIGN
    ↓
COMMUNITY FUNDING
    ↓
FUNDED
    ↓
SECRET DISCLOSED
    ↓
PLAINTEXT UNLOCKS
    ↓
PUBLIC btx:// MODEL
    ↓
FREE SWARM REPLICATION.
```

Lifecycle labels (`PUBLIC`, `FUNDING`, `FUNDED_AWAITING_RELEASE`,
`SECRET_DISCLOSED`, `PUBLIC_RELEASED`, `REFUND_AVAILABLE`, …) are **model-plane
UI/API states**. They are not consensus, not fork choice, and not a global
census.

## Static vs dynamic

**Publisher-signed (static):** model identity, description, `release_id`,
target, SHA-256 `key_hash`, refund height, campaign created time.

**Observed (dynamic):** confirmed funded atoms, pledges, provider counts,
secret disclosed, refund maturity. Funding changes **must not** force a
search-record resign.

`pledged` is nonbinding local accounting. **Funded / confirmed funded** is
chain-backed when `value_known=true` and `funding_source=CHAIN_OBSERVATION`.
Never display “90% funded” for a 90% pledge.

Percentages are **display only**. Monetary decisions use integer atoms.
`automatic_spend_atoms` is always `0`.

Hashlock for new campaigns is **SHA-256** with assurance `KEY_RELEASE_ONLY`.
HASH160 campaign creation is rejected. The secret is not stored in search
records.

`btx-modeld` never holds wallet keys. Claim/refund reuse 0.34.6
`htlc_sha256` / `buildhtlcclaim` / `buildhtlcrefund`.

Preferred read APIs: `searchmodels`, `getmodeleconomyentry`, `getmodelfeed`,
`getmodelreleaseeconomics`, `preparefundmodelrelease` (unsigned plan).
