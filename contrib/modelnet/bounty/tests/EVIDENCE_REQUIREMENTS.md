# Test evidence requirements

The CSV is a proposed native-BTX execution matrix. It deliberately ships with every case NOT_RUN. The reference Python test log is separate and proves only specification fixtures.

For every native execution record: test ID; source SHA; binary path/hash; compiler and crypto-library versions; network/genesis/activation configuration; exact command; platform/hardware/topology; UTC start/end; random seed where relevant; result; log path/hash; reviewer; and any limitations.

Evidence classes: reference-only, native unit, property/fuzz, differential consensus/policy, regtest wallet, isolated process, namespace network, real WAN, real GPU, Qt GUI and sustained soak. A mock cannot satisfy a real-WAN gate. A signed report cannot satisfy a real evaluator-run gate without corresponding evidence. Source code presence cannot satisfy any execution gate.

FAIL, NOT_RUN, UNSUPPORTED_ENVIRONMENT and DEFERRED_WITH_APPROVAL are distinct. No completed row may lose its exact source/binary association after rebasing. At minimum, rerun directly affected cases plus full integration scenarios on final HEAD. Never certify release readiness by editing the matrix first and trying to make code fit it afterward.

The coordinator must implement real test entrypoints using the repository's current test conventions. Suggested commands are intentionally not fabricated here for tests that do not yet exist. Document and execute the actual generated test names, supported build configurations and scripts in the final implementation handoff.
