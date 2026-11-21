# Market CLI

The wrapper invokes the real `btx-cli` as an argument array with `-stdin`; it never shells a URI or embeds a recovery password in command-line arguments. It shares the node's RPC authentication and wallet restrictions. It does not implement a second signing engine.

Examples (all amounts are atoms; use a disposable regtest node first):

```sh
python3 contrib/swapnet/tools/btx_market.py --cli /path/to/btx-cli --regtest status
python3 contrib/swapnet/tools/btx_market.py --regtest offers
python3 contrib/swapnet/tools/btx_market.py --regtest --request inspect.json invite-inspect
python3 contrib/swapnet/tools/btx_market.py --regtest --request connect.json invite-connect
python3 contrib/swapnet/tools/btx_market.py --regtest --request publish.json publish
python3 contrib/swapnet/tools/btx_market.py --regtest --request request.json request-public
python3 contrib/swapnet/tools/btx_market.py --regtest --request preview.json preview
python3 contrib/swapnet/tools/btx_market.py --regtest --request confirmation.json confirm
```

Use `--help` for the exact command spelling and fields shipped by the wrapper. The request files are ordinary method objects, not positional lists; the wrapper supplies one object to the RPC. Never put real keys or a passphrase into a shared example. An inspect call has no network side effects; an explicit connect call requests one peer connection; neither grants spend authority.

The reviewed Atlas UI is preferable for interactive monetary consent. CLI confirmation is an explicit operator action and must use a preview generated for the same authenticated principal and wallet.
