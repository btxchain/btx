# HCP authority matrix

| Actor | May | Must not |
|---|---|---|
| btxd | monetary consensus, wallet funding templates | OAuth, HCP HTTP, capability public HTTP |
| btx-modeld | package codec, PQ1, helper unix including private HCP connector methods | public HTTP capability, custody signing, generic `/rpc` |
| btx-capabilityd | owner-local grants, ensure/plan | hosted finance, OAuth |
| btx-hcpd | 34 typed REST ops, lab OAuth, ledger intents | consensus, wallet RPC, inbound runtime ports |
| btx-hosted | walletless accept/plan/ensure | start wallet/mining, custody keys |
| Browser portal | catalogue display, pairing UX | custody keys, wallet RPC, token-in-URI |
| HostedAccountPolicy | CEX spend bounds | local runtime admission |
| LocalCapabilityGrant | local acquire/run | spend, remote inference |
| FinancialReceipt | HOSTED_ATTESTED observation | consensus-ready, runtime-ready |
