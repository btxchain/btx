# HCP/1 baseline freeze (BTX-HCP-001)

- Tree: `/home/administrator/btx-0.34.7-private`
- Branch: `feat/0.34.8-modelnet-first-run`
- Candidate fingerprint (source HEAD at freeze): `573b4aa41f26ea6c61a00ee6096c5ff4de319335` plus dirty 0.34.8 HCP work
- Spec: `doc/modelnet/hcp/02_Hosted_Control_Plane_Implementation_Spec.md`
- Schemas: `src/modelnet/hcp/schemas/`
- Native codec: `src/modelnet/hcp_codec.cpp` (BTX-PJSON1 + `BTX/HCP/{type}/v1` SHA-384 body_id + ML-DSA-44)
- Gateway: `btx-hcpd` loopback HTTP, 34 typed operations, no `/rpc` passthrough
- Connector: `btx-hosted` walletless preset; helper methods are not public unix surface
- `automatic_spend_atoms` stays **0**
- QUIC remains NONSHIPPING
- Consensus / ASERT / header-PoW untouched
- Production `btxd.real` / CUDA attestor not replaced
- Evidence tiers: REFERENCE (contrib/modelnet/hcp-reference, SIMULATION_ONLY), NATIVE_UNIT (132 BOOST), PROCESS_E2E (`feature_modelnet_hcp.py` + `feature_modelnet_hcp_journeys.py` J01–J12), OAUTH_LAB (loopback `GET /lab/*`, not a live CEX IdP), CUSTODY_LAB (BTX_NATIVE_TEMPLATES lab), NATIVE_CHAIN (in-process confirm/reorg model; live mempool/HSM NOT_RUN)
- Isolated prefix: `~/.local/opt/btx-0.34.8-regtest/bin` (`btx-hcpd 0.34.8-dev HCP/1`). Production attestor not replaced.

Honest NOT_RUN until operator hardware/credentials exist:

- Live CEX IdP (not the in-process OAUTH_LAB)
- Live custody HSM
- Live CUDA DMA (LOCAL-06 tests the fence without GPU)
- WITH_MODELNET=OFF second cmake tree (disk policy)
- F2 wallet-signed fail-closed, `-modelindex`, BUILD_GUI=OFF, 400GiB payload, uTP/QUIC, torrentd
