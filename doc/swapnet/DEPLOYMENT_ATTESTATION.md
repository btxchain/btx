# Owner-selected EVM deployment provenance

Runtime bytecode equality alone does not establish trustworthy construction: creation code may initialize storage before returning the expected runtime. New EVM obligations therefore require an operator-selected creation manifest and independently observed deployment provenance.

The manifest binds network/genesis, chain ID, contract, creation transaction, expected creation-code hash and runtime hash. A direct CREATE deployment must have the expected null destination and receipt contract address. A CREATE2 profile additionally binds the factory, exact salt/initcode input, expected factory runtime and deterministic address. The observer reads a successful canonical receipt and sufficient finalized context, then rechecks canonical block identity to avoid assembling a proof across a reorg.

The expected creation hash must come from a reproducible local build/release manifest, not from the maker or an invitation. “Manifest supplied” is not itself proof. A chain unavailable during setup causes refusal of new obligations; the additional guard is not inserted into ongoing claim/refund recovery.

No network-specific deployed address is fabricated in this package. Run the maintained Foundry build using its pinned compiler settings, derive hashes and verify the actual deployment on each supported network. Retain transaction, code and block receipts with the exact candidate source.
