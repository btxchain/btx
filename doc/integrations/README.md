# BTX integration documentation

Start here for **BTX Custody Profile 1 (BCP/1)** / **BTX Exchange Profile v1** (`BTX_EXCHANGE_PROFILE_V1`): a vendor-neutral, monetary-only custody surface. It does not require HCP, the Model Network, mining, or a GPU.

| Document | Audience | Contents |
|---|---|---|
| [exchange-custody.md](exchange-custody.md) | Listing / custody FAQ | UTXO model, watch-only topology, deposit pools, batching, events, reorg — first page |
| [bcp1.md](bcp1.md) | Integrators | Profile contract, RPC list, ZMQ/event mapping, confirmation & reorg semantics, fees/dust |
| [external-sign.md](external-sign.md) | Signer engineers | Unsigned → digest → sign → finalize → broadcast; BTXPSBT; `SignerProvider` adapters |
| [key-link.md](key-link.md) | Custody vendors | Stage 1 raw/PQ signing vs stage 2 native asset; Key-Link / HSM attachment (examples only) |
| [incident-recovery.md](incident-recovery.md) | Operations | Reorg un-credit, node crash, signer outage, deposit-pool restore |

Also useful (outside this directory):

- Existing `-signer` command protocol: [../external-signer.md](../external-signer.md)
- Descriptor / watch-only key management: [../btx-key-management-guide.md](../btx-key-management-guide.md)
- Machine-readable network parameters: [../../contrib/bcp1/network-manifest.json](../../contrib/bcp1/network-manifest.json)
- Regtest certification harness: [../../contrib/bcp1/README.md](../../contrib/bcp1/README.md)

Venue, HSM, and Key-Link product names in these docs are **adapter examples**, not consensus requirements or a listing claim.
