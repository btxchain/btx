# Economics — models and money, not inference tariffs

The meaningful loop: **BTX can pay for model access and delivery while
independent nodes preserve content.** Mining is an optional source of
funds. Hosting does not require mining.

## What is paid

- Optional **delivery** when free supply cannot finish required ranges.
- Optional **public secret release** campaigns (B0), settled with 0.34.6
  SHA-256 HTLCs. `preparemodelfunding` / `signmodelfunding` /
  `submitmodelfunding` freeze an exact round on the helper and on `btxd`.
  `buildmodelhtlcclaim` / `buildmodelhtlcrefund` build unsigned 0.34.6
  SHA-256 templates. HASH160 `htlc_tx` is recovery-only. There is no
  `htlc_sha256_tx`.

Buyers or sponsors pay in ordinary BTX. A sponsor may pay a mirror while
downloaders still see price zero.

## What is not paid, and does not exist

- Remote or metered **inference**
- Protocol emissions or token rewards for hosting or advertised capacity
- Compulsory staking or a storage token
- Privileged release-pool commission
- Ranking a host higher because it mines or holds BTX
- Translating “I seeded a model” into BanMan exemption, ForceRelay, or
  cheaper block propagation

`NODE_MATMUL_ECONOMIC` on the monetary plane means partial monetary
validation. It is **not** a model marketplace bit.

## Free-first

Someone still supplies disk, electricity, and egress. Demand-seed (D11)
turns intentional downloads into replicas inside the operator's budget.
Preserve-rare is explicit. Paid mirrors remain for genuine scarcity.

Automatic spend default is **0 atoms**. `FREE_ONLY` never converts to paid
because a timer expired. See [free-first-policy.md](free-first-policy.md).

## Metrics that count

Count verified downloads, fulfilled paid tranches (when they exist),
bytes actually served, refunds, retention of roots, and source
diversity. Do **not** count self-issued ads, unsigned pledges, or
self-trades.

## Claims permitted vs not

Permitted after the relevant tests: native discovery and free transfer
integrated into BTX; CPU routers can introduce hosts; model activity is
outside monetary consensus.

Not permitted without extra evidence: “every node can run every model”;
“models are proven useful/safe”; “permanent storage guaranteed”;
“post-quantum anonymity”; “automatic fair exchange of arbitrary models.”

Structural qualification (`btx-modelcheck`) is **not** usefulness, safety,
or alignment.
