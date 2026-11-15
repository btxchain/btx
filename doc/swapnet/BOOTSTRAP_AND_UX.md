# Bootstrap and user experience

The zero-configuration promise applies to native discovery: an ordinary node starts SwapNet, exchanges a genesis-bound v2 hello over established BTX connections, requests live signed provider records, and exposes accurate status RPCs. Bootstrap inherits BTX peer discovery. There is no fabricated list of providers or requirement to trust a hosted registry.

The product separates these states: enabled; connected to compatible peers; live provider found; local chain verifier ready; correct wallet selected/unlocked; mandate installed; exact quote accepted; funding/recovery prepared; funding verified; claim/refund complete. These are not collapsed into a misleading green "ready" badge.

BTC/ETH transactions still require actual local external-chain verification, independent signing authority and funded fees. A node cannot honestly conjure those from no credentials and no assets. The host auto-detects supported existing Bitcoin installations; explicit owner policy covers nonstandard local paths and EVM contract deployments. Those are financial prerequisites, not peer-supplied customization.

A consumer can browse without a spending mandate. A maker advertises only after the owner enables an authorized market. An agent can use a scoped mandate without possessing either the native PQ secret or the EVM private account key. The normal CLI and Qt RPC console use the same API; there is no parallel web-only implementation.
