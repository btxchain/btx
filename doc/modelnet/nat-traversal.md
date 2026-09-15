# NAT traversal (model plane)

`AttemptModelPortMap` uses existing BTX PCP/NAT-PMP (`common/pcp.h`) on
the **model** listen port only (default 29447).

Never mapped: wallet RPC, monetary RPC, hidden attestor endpoints.

Rules:

- do not block `btxd`/helper startup waiting for a gateway
- renew before expiry (`MappingRenewalDue`)
- delete owned mappings on shutdown
- mapping success still requires reachability proof before
  `advertised_host`

IPv6 global addresses are preferred when **dial-back** proves them.
An interface having a `2000::/3` address is not sufficient.
