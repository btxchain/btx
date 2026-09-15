# Read-only reference explorer

Serve these files from the same origin as an implementation of the documented read-only browser bridge. No server or BTX implementation is included here. Pages expect a normalized `items[]` response and `next_cursor`; the integration agent must adapt the bridge to the final frozen API contract and demonstrate it.

This sample uses textContent, bounded input, explicit Search, cancellation and read-only endpoints. It sends no credentials and never calls a wallet/signing API. Production CSP should permit only self-hosted script/style/connect resources. It is a front-end contract example, not a verified live BTX explorer.
