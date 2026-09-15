# Provider exchange (PEX-style)

`POST /btx-model/2/ext/pex` exchanges bounded provider **hints**.

Hints expire, are rate-limited, and cannot advertise wallet/RPC/attestor
ports. They are not written to monetary AddrMan. PQ1 is still required
before any transfer. PEX is acceleration, not an authority.
