"""Entry points called only by the compiled, isolated CPython node host.

No HTTP server or helper process is launched. Native callbacks carry authenticated
RPC roles out-of-band. The peer transport can call on_message, never rpc. Only a
fixed allowlist can reach the native wallet; PQ secret material never returns.
"""
import json
import os
from pathlib import Path
import sys
import time
from decimal import Decimal
from urllib.parse import quote
from .errors import SwapError,require
from .assets import Asset
from .application import Application,NativeIdentity
from .authorization import Principal
from .journal import Journal
from .store import Store
from .vault import ForeignKeyVault,atomic_private_write
from .drivers import UTXODriver
from .evm_driver import EVMDriver
from .rpcclient import LocalRPC,discover_bitcoin
from .recovery import export_bundle

NATIVE_METHODS=frozenset({'getblockchaininfo','getblockhash','getblockcount','getbestblockhash','getblockheader','getblock',
 'getrawtransaction','gettxout','getmempoolentry','gettxspendingprevout','getdescriptorinfo','deriveaddresses','validateaddress',
 'decodescript','decodepsbt','decoderawtransaction','createpsbt','finalizepsbt','sendrawtransaction','testmempoolaccept',
 'listwallets','getwalletinfo','getnewaddress','getaddressinfo','listunspent','lockunspent','gettransaction','listtransactions',
 'exportpqkey','walletcreatefundedpsbt','walletprocesspsbt','importdescriptors','signmessage','verifymessage','_swapnet_import_htlc'})

class Host:
    def __init__(self,config_json,core_call,send):
        self.config=json.loads(config_json);self.core_call=core_call;self.send=send;self.errors=[]
        self.network=self.config['network'];self.directory=Path(self.config['datadir'])/'swapnet'
        require(not self.directory.is_symlink(),'DATABASE_PATH','SwapNet directory cannot be a symlink')
        self.directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.store=Store(self.directory/'state.sqlite');self.journal=Journal(self.store)
        require(self.store.db.execute('SELECT count(*) FROM sessions').fetchone()[0]==0,'LEGACY_STATE','Legacy observer sessions require offline review; preserve their database and native wallet')
        self._wallet=self.config.get('wallet','') or self.journal.setting('native_wallet','')
        keypath=self.directory/'vault.key'
        if not keypath.exists():atomic_private_write(keypath,os.urandom(32))
        require(keypath.is_file() and not keypath.is_symlink(),'VAULT_PATH','Unsafe wrapping key')
        if os.name!='nt':require(keypath.stat().st_uid==os.getuid() and not keypath.stat().st_mode&0o077,'VAULT_PERMISSIONS','Wrapping key must be private')
        master=keypath.read_bytes();require(len(master)==32,'VAULT_FORMAT','Wrong wrapping key length')
        self.vault=ForeignKeyVault(self.directory/'foreign-vault.json',master)
        if not self.vault.path.exists():self.vault.save()
        self.identity=NativeIdentity(self.network,self.journal,self.native,self.wallet)
        native_asset=Asset('btx',self.network).id
        self.drivers={native_asset:UTXODriver(native_asset,self.native,self.wallet,self.wallet,self.journal,self.vault,
                           network=self.network,confirmations=self.config.get('btx_confirmations',20))}
        self.startup_errors={}
        policies=self.journal.setting('asset_policies',{})
        for asset,policy in policies.items():
            try:self.drivers[asset]=self.configure_asset(policy)
            except SwapError as e:self.startup_errors[asset]=e.code
        # Discover an already-running same-network Bitcoin node without new ports,
        # installers, downloaded binaries, seeds, or assumptions about liquidity.
        # Never substitute a discovered wallet for an explicit Bitcoin policy
        # that failed validation during restore.
        if not any(asset.startswith('btc:') for asset in policies):
            try:self.auto_bitcoin()
            except SwapError as e:self.startup_errors['bitcoin_auto']=e.code
        self.app=Application(self.store,self.network,self.identity,self.vault,self.drivers,self.send,
                             configure_asset=self.configure_asset,wallet_info=self.wallet_info,
                             export_recovery=lambda passphrase:export_bundle(self.journal,self.directory,passphrase,self.network))
        for asset,driver in self.drivers.items():
            try:driver.relock()
            except SwapError as e:self.startup_errors[asset]=e.code
    def native(self,method,*params):return self._call('',method,params)
    def selected_wallet(self):
        wallets=self.native('listwallets')
        require(type(wallets) is list,'WALLET_STATE','Native wallet list unavailable')
        if self._wallet:
            require(self._wallet in wallets,'WALLET_UNLOADED','Bound SwapNet wallet is not loaded');return self._wallet
        require(len(wallets)==1,'WALLET_SELECTION','Load exactly one wallet or set -swapnetwallet; discovery remains available')
        self._wallet=wallets[0];self.journal.set_setting('native_wallet',self._wallet);return self._wallet
    def wallet(self,method,*params):return self._call(self.selected_wallet(),method,params)
    def _call(self,wallet,method,params):
        require(method in NATIVE_METHODS,'NATIVE_METHOD','Native method is outside the internal allowlist')
        try:
            raw=self.core_call(wallet,method,json.dumps(list(params),separators=(',',':'),allow_nan=False))
            require(type(raw) is str and len(raw)<=4_194_304,'RPC_RESPONSE_LIMIT','Native result exceeds bound')
            return json.loads(raw,parse_float=Decimal)
        except SwapError:raise
        except Exception as e:raise SwapError('NATIVE_RPC','Native chain/wallet operation failed; inspect the node status') from e
    def _bitcoin(self,rpc,policy=None):
        policy=policy or {};info=rpc('getblockchaininfo')
        native_chain=self.config.get('chain','main')
        expected='main' if native_chain=='main' else 'regtest' if native_chain=='regtest' else native_chain
        require(info['chain']==expected,'GENESIS_MISMATCH','Automatic Bitcoin discovery must match the native network class')
        asset=Asset('btc',rpc('getblockhash',0)).id
        if policy:require(policy['asset']==asset,'GENESIS_MISMATCH','Configured Bitcoin genesis differs')
        wallets=rpc('listwallets');selected=policy.get('wallet','')
        if selected:require(selected in wallets,'WALLET_UNLOADED','Configured Bitcoin wallet is not loaded')
        else:require(len(wallets)==1,'WALLET_SELECTION','Bitcoin requires one loaded wallet or an explicit local wallet policy');selected=wallets[0]
        wrpc=LocalRPC(rpc.url.rstrip('/')+'/wallet/'+quote(selected,safe=''),cookie_path=rpc.cookie_path,timeout=rpc.timeout)
        watch=wrpc
        if 'watch_wallet' in policy:
            observer=policy['watch_wallet']
            require(type(observer) is str and 0<len(observer)<=256 and observer!=selected and observer in wallets,
                    'WATCH_WALLET','Select a separate loaded Bitcoin watch wallet')
            watch=LocalRPC(rpc.url.rstrip('/')+'/wallet/'+quote(observer,safe=''),
                           cookie_path=rpc.cookie_path,timeout=rpc.timeout)
            watch_info=watch('getwalletinfo')
            require(watch_info.get('descriptors') is True and watch_info.get('private_keys_enabled') is False,
                    'WATCH_WALLET','Bitcoin watch wallet must use descriptors and disable private keys')
        hrp={'main':'bc','regtest':'bcrt'}.get(info['chain'],'tb')
        return UTXODriver(asset,rpc,wrpc,watch,self.journal,self.vault,network=self.network,hrp=hrp,
                          fee_rate=policy.get('fee_rate',2),confirmations=policy.get('confirmations',6))
    def auto_bitcoin(self):
        chain=self.config.get('chain','main')
        if chain not in {'main','regtest','signet','testnet4'}:return
        rpc=discover_bitcoin(Path.home(),chain,sys.platform)
        if rpc:
            driver=self._bitcoin(rpc)
            if driver.asset.id not in self.drivers:self.drivers[driver.asset.id]=driver
    def configure_asset(self,policy):
        require(type(policy) is dict,'ASSET_POLICY','Asset policy must be an object')
        allowed={'asset','rpc_url','cookie_path','wallet','watch_wallet','fee_rate','confirmations','contract','runtime_hash'}
        require(set(policy)<=allowed and {'asset','rpc_url'}<=set(policy),'ASSET_POLICY','Unsupported or missing asset policy fields')
        asset=Asset.parse(policy['asset']);require(asset.family in {'btc','evm'},'ASSET_POLICY','Native BTX binding is immutable')
        rpc=LocalRPC(policy['rpc_url'],cookie_path=policy.get('cookie_path'))
        if asset.family=='btc':return self._bitcoin(rpc,policy)
        require('watch_wallet' not in policy,'ASSET_POLICY','Watch wallet is Bitcoin-only')
        require({'contract','runtime_hash'}<=set(policy),'ASSET_POLICY','EVM requires the deployed address and exact runtime code hash')
        return EVMDriver(asset.id,rpc,self.journal,self.vault,policy['contract'],policy['runtime_hash'])
    def wallet_info(self):
        loaded=False;warning=None
        try:
            wallets=self.native('listwallets')
            loaded=(self._wallet in wallets) if self._wallet else len(wallets)==1
            if self._wallet and self._wallet not in wallets:
                warning='Bound wallet is not loaded. loadwallet is required after a restart; createwallet does not reload it.'
        except SwapError as e:
            warning=e.code
        out={'native_wallet':self._wallet,'wallet_loaded':loaded,'wallet_warning':warning,
             'identity':self.identity.peek(),'foreign_keys_separate':True,
             'wrapping_key_protection':'local-owner-filesystem','startup_errors':self.startup_errors,'foreign_accounts':[]}
        for asset,driver in self.drivers.items():
            if driver.family=='evm':out['foreign_accounts'].append({'asset':asset,'address':driver._account()[2]})
        return out
    def rpc(self,principal,owner,wallet,method,params_json):
        try:
            require(type(owner) is bool,'AUTH','Role must be supplied by native host')
            if wallet:
                if not self._wallet:
                    require(owner,'OWNER_REQUIRED','Only an owner may establish the native wallet binding')
                    require(wallet in self.native('listwallets'),'WALLET_UNLOADED','Requested wallet not loaded')
                    self._wallet=wallet;self.journal.set_setting('native_wallet',wallet)
                require(wallet==self._wallet,'WALLET_SCOPE','RPC wallet differs from the bound SwapNet wallet')
            require(len(params_json)<=65536,'RPC_REQUEST_LIMIT','Request too large')
            params=json.loads(params_json)
            result=self.app.rpc(Principal(principal,owner,wallet or self._wallet),method,params)
            return json.dumps({'result':result},separators=(',',':'),allow_nan=False)
        except SwapError as e:return json.dumps({'error':e.as_dict()},separators=(',',':'))
        except (ValueError,KeyError,TypeError):return json.dumps({'error':{'code':'PARAMS','message':'Malformed request or local state'}})
    def on_peer(self,peer,connected):
        if connected:self.app.peer_connected(peer)
        else:self.app.peer_disconnected(peer)
    def on_message(self,peer,command,payload):
        # swprov "[]" is a list and raises AttributeError. Any peer payload
        # must be counted and dropped, not allowed to stop the worker.
        try:self.app.on_message(peer,command,payload)
        except SwapError as e:self.app.note_packet_error(e.code,e.message)
        except Exception:self.app.note_packet_error('PACKET','Rejected packet')
    def tick(self):
        try:self.app.tick()
        except SwapError as e:self.app.last_tick_error=e.as_dict()
    def close(self):self.app.close()
