# Schema usage

These are proposed strict JSON shape contracts for the implementation agents. They are not proof of deployed RPC compatibility. Semantic-checks.json is mandatory in addition to JSON Schema validation. Exact transaction/script validation and issuer authorization cannot be represented by JSON Schema alone.

Validate payload against its named schema and the outer record against SignedEnvelope. Sign the full canonical body using reference/CODEC.md, with existing BTX ML-DSA implementation. Do not treat the Python reference as a cryptographic verifier. ModelSearchRecordV2 replaces incomplete authentication semantics, not existing model IDs. Legacy records must retain explicit legacy provenance.

Human decimal percentages are derived views. Monetary values use canonical decimal strings and MoneyRange. Heights must remain block heights below 500000000. The coordinator freezes actual protocol numeric resource assignments after checking the live registry; this package does not presume unused numeric IDs.
