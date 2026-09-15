# Hole punching (DCUtR-inspired)

Prerequisite: A and B already talk through a relay (or equivalent
rendezvous).

1. Exchange candidate endpoints on the authenticated channel.
2. Estimate control-path RTT.
3. Attempt synchronized outbound connects.
4. Complete **direct** PQ1. Relay security state does not transfer.
5. On success, migrate model traffic to the direct socket.
6. On failure, keep the relay path.

Retries are bounded (3). After that, stay relayed until a network epoch,
mapping change, or operator request. Symmetric NAT is not an error if
relay still works. Do not thrash a working relay.

`POST /ext/holepunch` records the attempt. `classical_fallback` is always
false.
