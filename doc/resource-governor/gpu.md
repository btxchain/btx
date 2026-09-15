# GPU / accelerator policy

Mining never degrades ExactReplay. `CandidateMining` in `pow.cpp` asks
`ResourceGovernor::MiningAllowed()` before `Acquire`. `WinnerReseal` of a
finished solution is not blocked. `VerifyBoundedExactReplay` takes a
TipValidation lease and calls `BeginValidationWork()` so mining yields even
while waiting.

The existing `RCAcceleratorScheduler` still preempts CandidateMining when
ActiveTipValidation arrives. Cooperative cancellation of an in-flight
episode uses that preempt latch. Discarding a partial mining attempt is
acceptable. Consensus validation is not.

Multi-GPU: `AcceleratorSample.reserved_for_validation` never mines.
`-governorgpu` / device lists are documented as operator config; AUTO must
not mine a reserved validator device.

Apple unified memory: GPU util alone is insufficient. Combined memory
pressure, thermal, and explicit validation/AI hooks govern mining. Mining
backs off under swap/memory pressure.

When mining pauses, intensity is 0 so the miner should not keep large
buffers. Setup-cost reuse is a miner implementation detail; the governor
only revokes the permit.

NVML is optional. Failure to initialize returns UNKNOWN metrics and
conservative intensity, never a disabled node.
