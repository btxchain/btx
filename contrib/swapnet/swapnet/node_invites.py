"""Signed, inert P2P invitations. Parsing never performs DNS, RPC, or a dial.

The signature binds advertised endpoints to a provider key; it is not a proof
that the eventual TCP peer possesses that key. Quotes and agreements are still
verified end-to-end. Only an owner-reviewed connect RPC may request a dial.
"""
from __future__ import annotations
import base64
import ipaddress
import re
from urllib.parse import urlsplit
from .canonical import dumps,loads,digest,exact_fields,hex32,integer
from .errors import require,SwapError

PREFIX='btx://swapnet/v1/'
DOMAIN='BTX/SWAPNET/INVITE/1'
MAX_URI=32768
FIELDS={'version','network','provider','endpoints','issued_at','expires_at','nonce'}


def endpoint(value:str,*,allow_private:bool=False)->dict:
    require(type(value) is str and 0<len(value)<=300,'INVITE_ENDPOINT','Endpoint is too long')
    require(not any(c.isspace() or ord(c)<32 for c in value) and not any(c in value for c in '/?#@%\\'),
            'INVITE_ENDPOINT','An endpoint is host:port, never a URL, RPC address, credential, or path')
    try:
        parsed=urlsplit('tcp://'+value)
        host=parsed.hostname;port=parsed.port
        require(host is not None and port is not None and 1<=port<=65535,
                'INVITE_ENDPOINT','Explicit P2P port required')
    except ValueError as e:raise SwapError('INVITE_ENDPOINT','Malformed endpoint') from e
    require(parsed.username is None and parsed.password is None,'INVITE_ENDPOINT','Credentials prohibited')
    host=host.lower()
    onion=host.endswith('.onion')
    if onion:
        require(re.fullmatch(r'[a-z2-7]{56}\.onion',host) is not None,
                'INVITE_ENDPOINT','Only Tor v3 service names are accepted')
        return {'endpoint':host+':'+str(port),'kind':'onion','requires_proxy':True,'private':False}
    try:ip=ipaddress.ip_address(host)
    except ValueError:
        require(len(host)<=253 and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',host) is not None,
                'INVITE_ENDPOINT','Invalid DNS hostname')
        labels=host.split('.')
        require(len(labels)>=2 and all(0<len(x)<=63 and not x.startswith('-') and not x.endswith('-') for x in labels),
                'INVITE_ENDPOINT','A fully-qualified hostname is required')
        require(host not in {'localhost','localhost.localdomain'} and not host.endswith(('.localhost','.local','.internal')),
                'INVITE_ENDPOINT','Local hostnames are not allowed in invitations')
        # DNS resolution is deferred to the normal BTX dial path AFTER review,
        # preserving configured SOCKS/name-proxy policy. Display this explicitly.
        return {'endpoint':host+':'+str(port),'kind':'dns','requires_proxy':False,
                'private':None,'dns_unresolved':True}
    require(not(ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local),
            'INVITE_ENDPOINT','Loopback, link-local, unspecified, and multicast addresses are prohibited')
    require(allow_private or ip.is_global,'INVITE_PRIVATE','Private or reserved address needs explicit local consent')
    canonical=('['+ip.compressed+']' if ip.version==6 else ip.compressed)+':'+str(port)
    return {'endpoint':canonical,'kind':'ipv6' if ip.version==6 else 'ipv4',
            'requires_proxy':False,'private':not ip.is_global}


def message(body:dict)->str:return DOMAIN+':'+digest(DOMAIN,body)


def create(identity,network,endpoints,now,ttl=86400,allow_private=False):
    integer(ttl,lo=60,hi=7*86400)
    require(type(endpoints) is list and 1<=len(endpoints)<=4,'INVITE_ENDPOINT','One to four endpoints required')
    canonical=[endpoint(x,allow_private=allow_private)['endpoint'] for x in endpoints]
    require(len(set(canonical))==len(canonical),'INVITE_ENDPOINT','Duplicate endpoint')
    import secrets
    body={'version':1,'network':hex32(network),'provider':identity.address(),'endpoints':canonical,
          'issued_at':now,'expires_at':now+ttl,'nonce':secrets.token_hex(32)}
    env={'body':body,'signature':identity.sign(message(body))}
    token=base64.urlsafe_b64encode(dumps(env)).decode().rstrip('=')
    uri=PREFIX+token
    require(len(uri)<=MAX_URI,'INVITE_SIZE','Signed invitation is too large')
    return {'uri':uri,'envelope':env,'spending_authority':False,'connection_started':False}


def inspect(uri,network,now,verify,allow_private=False):
    require(type(uri) is str and len(uri)<=MAX_URI and uri.startswith(PREFIX),
            'INVITE_URI','Not a supported SwapNet invitation')
    token=uri[len(PREFIX):]
    require(re.fullmatch(r'[A-Za-z0-9_-]+',token) is not None,'INVITE_URI','Invalid invitation encoding')
    try:
        raw=base64.b64decode(token+'='*((-len(token))%4),altchars=b'-_',validate=True)
        require(base64.urlsafe_b64encode(raw).decode().rstrip('=')==token,'INVITE_URI','Noncanonical encoding')
        env=loads(raw)
    except (ValueError,UnicodeError) as e:raise SwapError('INVITE_URI','Malformed invitation') from e
    exact_fields(env,{'body','signature'});b=env['body'];exact_fields(b,FIELDS)
    require(type(b['version']) is int and b['version']==1,'INVITE_VERSION','Unsupported invitation')
    require(hex32(b['network'])==network,'NETWORK','Invitation belongs to another chain')
    hex32(b['nonce']);integer(b['issued_at']);integer(b['expires_at'])
    require(b['issued_at']<=now<b['expires_at']<=b['issued_at']+7*86400,
            'INVITE_EXPIRED','Invitation expired or future-dated')
    require(type(b['provider']) is str and 0<len(b['provider'])<=256,'IDENTITY','Invalid provider')
    require(type(b['endpoints']) is list and 1<=len(b['endpoints'])<=4,'INVITE_ENDPOINT','Invalid endpoint list')
    endpoints=[endpoint(x,allow_private=allow_private) for x in b['endpoints']]
    require(len({x['endpoint'] for x in endpoints})==len(endpoints),'INVITE_ENDPOINT','Duplicate endpoint')
    require(type(env['signature']) is str and 0<len(env['signature'])<=16384,'SIGNATURE','Invalid signature')
    require(verify(b['provider'],env['signature'],message(b)) is True,'BAD_SIGNATURE','Invitation signature rejected')
    return {'invitation_id':digest(DOMAIN+'/RECORD',env),'provider':b['provider'],'network':b['network'],
            'expires_at':b['expires_at'],'endpoints':endpoints,'signature_verified':True,
            'transport_identity_proven':False,'connection_started':False,'spending_authority':False,
            'envelope':env}
