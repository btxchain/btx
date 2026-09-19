"""Provider-neutral CRL/1.2 transport client.

Install the real provider authentication and native statement-verification
callbacks. This module never signs money, discovers credentials, follows
redirects, or retries mutations. It uses the supplied operation catalogue.
"""
from __future__ import annotations
import json, re, hashlib
from pathlib import Path
from typing import Callable, Mapping, Any
from urllib.parse import urlsplit, urlencode, quote
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError

AUTOMATIC_SPEND_ATOMS = 0
_BLOCKED_OPS = frozenset({"executeAllocation", "submitFinanceIntent", "genericRpc", "/rpc"})

class ClientError(RuntimeError):
    pass

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ClientError('REDIRECT_REQUIRES_EXPLICIT_PROVIDER_POLICY')

class CrlClient:
    def __init__(self, base_url: str,
                 request_headers: Callable[[str,str,bytes], Mapping[str,str]],
                 verify_statement: Callable[[Mapping[str,Any]], None],
                 catalogue: Path | None = None, timeout: float = 30.0):
        u=urlsplit(base_url)
        if u.scheme != 'https' or not u.netloc or u.username or u.password or u.query or u.fragment:
            raise ValueError('Use an explicitly enrolled HTTPS base origin and path.')
        self.base_url=base_url.rstrip('/')
        self.headers=request_headers
        self.verifier=verify_statement
        self.timeout=timeout
        self.opener=build_opener(_NoRedirect())
        self.automatic_spend_atoms = AUTOMATIC_SPEND_ATOMS
        here=Path(__file__).resolve().parent
        p=catalogue or (here/'schemas'/'operations-v1.2.json' if (here/'schemas'/'operations-v1.2.json').is_file() else here.parent/'schemas'/'operations-v1.2.json')
        ops=json.loads(p.read_text())['operations']
        for o in ops:
            path=o['path']
            if path=='/rpc' or path.startswith('/rpc') or not path.startswith('/btx/hcp/v1/'):
                raise ClientError('GENERIC_RPC_DISABLED')
            if o['operation_id'] in _BLOCKED_OPS:
                raise ClientError('SCOPE_DENIED')
        self.operations={o['operation_id']:o for o in ops}

    def executeAllocation(self, *args, **kwargs):
        raise ClientError('SCOPE_DENIED: CRL/1.2 has no executeAllocation route')

    def call(self, operation_id: str, *, path: Mapping[str,str] | None=None,
             query: Mapping[str,str] | None=None, body: Any=None,
             idempotency_key: str | None=None) -> Any:
        if operation_id in _BLOCKED_OPS:
            raise ClientError('SCOPE_DENIED: not a CRL/1.2 typed route')
        if operation_id not in self.operations:
            raise ClientError('UNKNOWN_OPERATION')
        o=self.operations[operation_id]
        if o['path']=='/rpc' or o['path'].startswith('/rpc') or not o['path'].startswith('/btx/hcp/v1/'):
            raise ClientError('GENERIC_RPC_DISABLED')
        relative=o['path'].removeprefix('/btx/hcp/v1')
        if '/execute' in relative:
            raise ClientError('SCOPE_DENIED: CRL/1.2 client does not call execute paths')
        needed=set(re.findall(r'\{([^}]+)\}',relative))
        if set(path or {}) != needed:
            raise ValueError('Path parameters must exactly match the operation.')
        for k,v in (path or {}).items():
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}',v):
                raise ValueError('Invalid opaque path identifier')
            relative=relative.replace('{'+k+'}',quote(v,safe=''))
        url=self.base_url+relative
        if query:
            url+='?'+urlencode(query)
        method=o['method']
        if method=='POST' and (not idempotency_key or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}',idempotency_key)):
            raise ValueError('A stable Idempotency-Key is required for every POST.')
        if o['request_schema']=='BINARY':
            if not isinstance(body,bytes) or not 0<len(body)<=16*1024*1024:
                raise ValueError('Binary chunk must contain 1..16 MiB.')
            data=body;content_type='application/octet-stream'
        else:
            data=b'' if body is None else json.dumps(body,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
            if len(data)>1048576:raise ValueError('JSON body exceeds 1 MiB.')
            content_type='application/json'
        headers=dict(self.headers(method,url,data))
        headers['Accept']='application/json';headers['Content-Type']=content_type
        if idempotency_key:headers['Idempotency-Key']=idempotency_key
        if o['request_schema']=='BINARY':headers['X-Content-SHA384']=hashlib.sha384(data).hexdigest()
        request=Request(url,data=data if method=='POST' else None,headers=headers,method=method)
        try:
            with self.opener.open(request,timeout=self.timeout) as response:
                limit=16*1024*1024 if o['response_schema']=='BINARY' else 1048576
                raw=response.read(limit+1)
                if len(raw)>limit:raise ClientError('RESPONSE_TOO_LARGE')
                if o['response_schema']=='BINARY':return raw
                value=json.loads(raw)
        except HTTPError as e:
            # Do not replay. Caller inspects stable state and existing operation ID.
            raw=e.read(8192).decode('utf-8',errors='replace')
            raise ClientError(f'HTTP {e.code}: {raw}') from e
        if isinstance(value,dict) and 'object_type' in value:
            self.verifier(value)  # Must use enrolled authority and native verification.
        return value
