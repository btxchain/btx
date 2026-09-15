# BTX resource governor

BTX uses spare capacity, not user capacity.

Foreground AI, ExactReplay validation, and user-requested model retrieval
always outrank opportunistic mining, seeding, and preservation.

The governor is a **local policy engine**. It never enters headers, work
validity, fork choice, difficulty, issuance, or transaction validity.
`automatic_spend_atoms` stays 0.

Default mode is `AUTO`. Mining consent is separate: `-automining` only
schedules work after mining is already enabled (`-gen` or first-run mining
checkbox). It does not silently turn a wallet into a miner.

## Components

- `src/node/resource_governor.*` — policy, hysteresis, permits (bitcoin_common)
- `src/rpc/resource_governor.cpp` — RPCs (always compiled)
- `src/pow.cpp` — CandidateMining gated; WinnerReseal not gated
- `VerifyBoundedExactReplay` — Begin/EndValidationWork (validation always wins)
- `btx-modeld` reads `modelnet/governor-permit.json` for upload/preservation

## Modes

`AUTO` `PERFORMANCE` `BALANCED` `ECO` `MANUAL` `OFF`

## RPC

`getresourcegovernorinfo` `setresourcegovernormode`
`getresourcegovernorpolicy` `setresourcegovernorpolicy` `resetresourcegovernorpolicy`
`pausebackgroundwork` `resumebackgroundwork` `getbackgroundjobs`
`getmininggovernorinfo` `getmodelbandwidthinfo`

## Flags

`-resourcegovernor` `-automining` `-miningmaxintensity`
`-backgroundonbattery` `-backgroundonmetered`
`-governoridleseconds` `-governorcooldownseconds`
`-modeluploadlimit=auto|<size>`

Precedence: CLI > conf > GUI > mode defaults > platform.

See `policy.md`, `gpu.md`, `network.md`, `power.md`, `platforms.md`,
`reference-audit.md`.
