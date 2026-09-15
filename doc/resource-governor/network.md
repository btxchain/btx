# Network policy

Spare capacity is not binary idle. A 100 Mbps link using 5 Mbps has spare
capacity. AUTO seeding may use part of it without saturating a consumer
uplink.

Hysteresis (initial defaults):

- outbound util < 25% of ceiling: keep/raise seeding cap
- outbound util > 65% for a few seconds: reduce cap
- RTT > 2× baseline + 20 ms: latency backoff (divide by 4)

User-requested retrieval outranks seeding and preservation. Preservation
yields first. Reciprocal seeding may continue at a reduced ceiling for
control/ACK traffic.

Absolute operator `-modeluploadlimit` always wins over AUTO.
`governor-permit.json` `upload_bps` is the helper-facing ceiling.
`btx-modeld` token-buckets piece responses (HTTP 429 when exhausted).

No centralized telemetry. Latency baseline is local peers/gateway only.
