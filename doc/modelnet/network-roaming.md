# Network roaming

Laptops change networks. The model helper must not require a full BTX
restart.

`NetworkEpoch` increments on IPv4 change, IPv6 prefix change, Wi-Fi ↔
Ethernet, VPN attach/detach, DHCP, default-route change, and wake from
sleep.

On epoch:

- invalidate reachability proof (`DEGRADED`)
- re-run mapping (owned mappings are released on shutdown)
- re-check AutoNAT
- renew provider records / relay reservations
- reconnect; keep verified pieces on disk

Sleep: do not corrupt transfer state. On wake, assume NAT, external IP,
peers, and reservations may be stale. Re-establish asynchronously.

Monetary `btxd` is independent of these events.
