# Resource-governor policy

Priority (high to low):

1. Foreground user / agent
2. Monetary validation / ExactReplay
3. User-requested model retrieval
4. Interactive BTX operations
5. Reciprocal model seeding
6. Rare-model / rare-piece preservation
7. Mining
8. Non-urgent maintenance / GC

Independent dimensions: `cpu_idle` `gpu_idle` `network_spare` `disk_spare`
`thermal_ok` `power_ok` `memory_ok`.

Mining hysteresis (AUTO, `-automining=1`):

- resume when GPU util < 10% for 30s
- pause when GPU util > 35% for 3s
- cooldown 10s after pause

Intensity ramp: 0 → 25 → 50 → 75 → configured max. Unknown GPU telemetry
stays at 25% (conservative), never fail-open at 100%.

Validation and `BeginForegroundAiWork()` pause immediately.

Battery: background mining off unless `-backgroundonbattery=1`.
Metered: seeding/preservation reduced unless `-backgroundonmetered=1`.

Fail-closed: `SetUnavailable` pauses mining and preservation; model serving
uses a conservative static upload floor. Monetary validation continues.

Hard caps always win over AUTO. Attack-generated load is not permission to
raise ceilings.

Storage quota remains the adaptive-storage policy. Swarm scheduler still
picks peers/pieces. The governor only sets aggregate ceilings.
