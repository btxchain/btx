"""Owner-consented watch-wallet setup for an already-running, matching Bitcoin node.
Never installs software, imports secrets, sends coins, or accepts a peer RPC URL.
"""
from urllib.parse import quote
from .market_controls import require

def plan_setup(rpc,chain,wallet=None):
 info=rpc('getblockchaininfo')
 require(isinstance(info,dict) and info.get('chain')==chain,'GENESIS_MISMATCH','Bitcoin node is on a different network class')
 wallets=rpc('listwallets')
 require(type(wallets) is list and len(wallets)<=256 and all(type(w) is str and len(w)<=256 for w in wallets),
         'WALLET_STATE','Invalid Bitcoin loaded-wallet list')
 candidates=[w for w in wallets if not w.endswith('.swapnet-watch')]
 if wallet is None:
  if len(candidates)!=1:return {'selection_required':True,'loaded_funding_candidates':candidates,'spends_funds':False}
  wallet=candidates[0]
 require(wallet in wallets,'WALLET_UNLOADED','Chosen Bitcoin funding wallet is not loaded')
 watch=wallet+'.swapnet-watch'
 require(len(watch)<=256,'WATCH_WALLET','Derived watch-wallet name is too long')
 return {'selection_required':False,'funding_wallet':wallet,'watch_wallet':watch,
         'watch_wallet_loaded':watch in wallets,'creates_watch_wallet_only':watch not in wallets,
         'spends_funds':False,'requires_explicit_consent':True,'chain':chain}

def perform_setup(rpc,wallet_rpc_factory,chain,wallet=None,consent=False):
 require(type(consent) is bool,'CONSENT','Consent must be a boolean')
 plan=plan_setup(rpc,chain,wallet)
 if not consent or plan['selection_required']:return plan
 watch=plan['watch_wallet']
 if not plan['watch_wallet_loaded']:
  # Bitcoin Core's positional contract: name, disable_private_keys, blank,
  # passphrase, avoid_reuse, descriptors, load_on_startup.
  rpc('createwallet',watch,True,True,'',False,True,True)
 wrpc=wallet_rpc_factory(watch)
 info=wrpc('getwalletinfo')
 require(info.get('descriptors') is True and info.get('private_keys_enabled') is False,
         'WATCH_WALLET','Watch wallet must be descriptor-based with private keys disabled')
 plan.update(watch_wallet_loaded=True,ready_for_local_policy_binding=True)
 return plan
