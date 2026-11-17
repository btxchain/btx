"""Owner-reviewed Bitcoin verifier/watch-wallet setup; never peer configuration."""
from __future__ import annotations
from .assets import Asset
from .canonical import exact_fields
from .errors import require,SwapError
from .rpcclient import LocalRPC


def configure_bitcoin(host,policy):
    require(type(policy) is dict,'ASSET_POLICY','Bitcoin setup must be an object')
    require(set(policy)<= {'rpc_url','cookie_path','wallet','watch_wallet','fee_rate','confirmations'} and
            {'rpc_url','cookie_path','wallet'}<=set(policy),'ASSET_POLICY','Unsupported or missing Bitcoin setup field')
    rpc=LocalRPC(policy['rpc_url'],cookie_path=policy['cookie_path'])
    info=rpc('getblockchaininfo');expected=host.config.get('chain','main')
    require(info.get('chain')==expected,'GENESIS_MISMATCH','Bitcoin network class differs from BTX')
    require(not info.get('initialblockdownload',True),'CHAIN_SYNC','Bitcoin verifier is not synchronized')
    wallet=policy['wallet']
    require(type(wallet) is str and 0<len(wallet)<=128 and wallet in rpc('listwallets'),
            'WALLET_SELECTION','Select an already loaded Bitcoin funding wallet')
    watch=policy.get('watch_wallet',wallet+'.swapnet-watch')
    require(type(watch) is str and 0<len(watch)<=180 and watch!=wallet,'WATCH_WALLET','Select a separate watch wallet')
    loaded=rpc('listwallets')
    if watch not in loaded:
        names={r['name'] for r in rpc('listwalletdir').get('wallets',[])}
        if watch in names:rpc('loadwallet',watch,True)
        else:rpc('createwallet',watch,True,True,'',False,True,True)
    result={**policy,'asset':Asset('btc',rpc('getblockhash',0)).id,'watch_wallet':watch}
    # The existing factory verifies descriptors/private_keys_enabled=false,
    # exact genesis, wallet availability and the configured chain client.
    host._bitcoin(rpc,result).ready()
    return result
