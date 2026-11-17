# Shareable native SwapNet peer invitations

Format: `btx://swapnet/v1/<unpadded-base64url-canonical-envelope>`.

The provider signs version, exact network genesis, provider identity, 1–4 native BTX P2P endpoints, issued/expiry times and a nonce under `BTX/SWAPNET/INVITE/1`. A URI is capped at 32 KiB; the native startup inbox retains at most eight. It contains no application-level spend capability. An optional `.btx` document can contain exactly one URI; Atlas's bounded preview reader is reused.

The node's `inspectswapinvite` verifies without resolving or connecting. `connectswapinvite` is owner-only and calls one fixed native operation: `addnode(endpoint, "onetry")`. It cannot invoke arbitrary RPC, execute code, expose local RPC, set a proxy or configure a verifier. The native backend validates syntax and selected-endpoint membership again after the reviewed request.

Names and addresses are untrusted. Loopback, unspecified, multicast, link-local addresses, credentials, URL paths, control characters and malformed host/port pairs are rejected. Private/reserved addresses require a deliberate private-network override, and DNS names require a deliberate DNS override. Hostname resolution is delegated to native connection policy, so an operator must understand its proxy/onlynet settings and DNS-rebinding exposure. A signature does not prove control of a DNS name or bind a bare TCP handshake to the maker identity.

Tor names must have the expected v3 shape. Existing node Tor/proxy support performs the actual transport; the invitation does not bootstrap Tor or certify onion reachability. The signer must advertise an endpoint others can reach. NAT traversal is not implied by a link.

Atlas registers an inert command-line inbox and can consume native deep-link events where the existing host exposes them. Received links are presented as text before signature inspection. Browser previews never dial. A separate native review is required for the connection attempt; importing a link does not enable taker/maker modes or cause funding.

Unit and native functional tests cover malformed links, wrong networks, expired signatures, private-address policy, no-dial inspection, and the absence of new monetary reservations. Actual OS scheme registration and already-running-instance dispatch must be checked on each shipped desktop platform; no platform qualification is inferred from a JavaScript parser test.
