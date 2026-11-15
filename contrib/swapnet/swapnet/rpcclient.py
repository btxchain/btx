"""Local RPC clients with bounded responses, no proxy use, redirects or peer URLs.

This is an operator/testing adapter. Release packaging must connect monetary RPC
calls through the approved native authority broker, not hand the discovery helper
an unrestricted wallet RPC cookie. It never accepts endpoints from peer messages.
"""
import base64
import ipaddress
import json
from decimal import Decimal
import os
from pathlib import Path
import urllib.request
import urllib.parse
import urllib.error
from .errors import require,SwapError

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise SwapError('RPC_REDIRECT','RPC redirects forbidden')

class LocalRPC:
    def __init__(self,url,*,cookie_path=None,timeout=10):
        u=urllib.parse.urlsplit(url)
        require(u.scheme=='http' and not u.username and not u.password and not u.fragment and not u.query,'RPC_URL','Invalid local RPC URL')
        try:address=ipaddress.ip_address(u.hostname)
        except ValueError as e:raise SwapError('RPC_HOST','Use a literal loopback address, not DNS') from e
        require(address.is_loopback and u.port is not None,'RPC_HOST','Only loopback RPC is allowed')
        require(1<=timeout<=30,'RPC_TIMEOUT','Invalid RPC timeout')
        self.url,self.cookie_path,self.timeout=url,Path(cookie_path) if cookie_path else None,timeout
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def __call__(self,method,*params):
        require(type(method) is str and len(method)<=64,'RPC_METHOD','Invalid RPC method')
        payload=json.dumps({'jsonrpc':'2.0','id':'swapnet','method':method,'params':list(params)},allow_nan=False,separators=(',',':')).encode()
        headers={'Content-Type':'application/json'}
        if self.cookie_path:
            require(self.cookie_path.is_file() and not self.cookie_path.is_symlink(),'RPC_COOKIE','RPC cookie unavailable')
            if os.name!='nt':
                st=self.cookie_path.stat()
                require(st.st_uid==os.getuid() and not st.st_mode&0o077,'RPC_COOKIE','RPC cookie permissions unsafe')
            cookie=self.cookie_path.read_text().strip()
            require(0<len(cookie)<=4096 and ':' in cookie,'RPC_COOKIE','Malformed RPC cookie')
            headers['Authorization']='Basic '+base64.b64encode(cookie.encode()).decode()
        request=urllib.request.Request(self.url,data=payload,headers=headers)
        try:
            try: response=self.opener.open(request,timeout=self.timeout)
            except urllib.error.HTTPError as e:
                if e.code in (400,404,500):response=e
                else:raise
            with response:
                raw=response.read(4_194_305)
            require(len(raw)<=4_194_304,'RPC_RESPONSE_LIMIT','RPC response too large')
            obj=json.loads(raw,parse_float=Decimal)
            require(obj.get('id')=='swapnet','RPC_RESPONSE_ID','Unexpected RPC response ID')
            err=obj.get('error')
            if err is not None:
                detail=err.get('message') if type(err) is dict else None
                raise SwapError('CHAIN_RPC', detail[:300] if type(detail) is str and detail else 'Chain RPC rejected operation')
            require('result' in obj,'RPC_RESPONSE','Missing RPC result')
            return obj['result']
        except SwapError:raise
        except Exception as e:raise SwapError('RPC_UNAVAILABLE','Local chain client unavailable or returned invalid JSON') from e

def bitcoin_cookie_candidates(home,network='main',platform='linux'):
    require(network in {'main','regtest','testnet4','signet'},'NETWORK','Unknown Bitcoin network')
    home=Path(home)
    base=(home/'Library/Application Support/Bitcoin' if platform=='darwin' else
          home/'AppData/Roaming/Bitcoin' if platform=='win32' else home/'.bitcoin')
    directory=base if network=='main' else base/network
    return [directory/'.cookie']

def discover_bitcoin(home,network='main',platform='linux'):
    ports={'main':8332,'regtest':18443,'testnet4':48332,'signet':38332}
    for cookie in bitcoin_cookie_candidates(home,network,platform):
        if cookie.is_file():return LocalRPC('http://127.0.0.1:'+str(ports[network]),cookie_path=cookie)
    return None
