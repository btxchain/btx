"""Real local RPC timeouts + durable coordinator; simulated chains/signing."""
from contextlib import contextmanager
import base64
import json
import socket
import threading
import urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import pytest
from swapnet.errors import SwapError
from swapnet.rpcclient import LocalRPC
from test_refused_connection_recovery import funded_pair, wire, identities, A

@contextmanager
def timeout_endpoint(path,mode,status=200):
    cookie=path/'.cookie';cookie.write_text('test:disposable');cookie.chmod(0o600)
    state={'healthy':False,'methods':[],'stop':threading.Event()}
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.headers['Authorization']=='Basic '+base64.b64encode(b'test:disposable').decode()
            obj=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            state['methods'].append(obj['method']);assert obj['method']=='getblockcount'
            body=json.dumps({'id':obj['id'],'result':100,'error':None}).encode()
            if mode=='headers' and not state['healthy']:
                state['stop'].wait(25);return
            self.send_response(status);self.send_header('Content-Length',str(len(body)));self.end_headers()
            try:
                if state['healthy']:self.wfile.write(body)
                else:self.wfile.write(body[:1]);self.wfile.flush();state['stop'].wait(25)
            except (BrokenPipeError,ConnectionResetError):pass
        def log_message(self,*args):pass
    class Server(ThreadingHTTPServer):daemon_threads=False
    guard=socket.socket();guard.bind(('127.0.0.1',0));port=guard.getsockname()[1]
    server=thread=None
    def start():
        nonlocal server,thread
        guard.close();server=Server(('127.0.0.1',port),Handler)
        thread=threading.Thread(target=server.serve_forever);thread.start()
    if mode!='connect':start()
    def recover():
        state['healthy']=True
        if server is None:start()
    client=LocalRPC('http://127.0.0.1:'+str(port),cookie_path=cookie,timeout=1)
    if mode=='connect':
        # Portable maintained control. Real Darwin connect-timeout evidence is
        # retained separately; bound sockets may refuse immediately elsewhere.
        original_opener=client.opener
        class ConnectionTimeout:
            def open(self,*args,**kwargs):
                if state['healthy']:return original_opener.open(*args,**kwargs)
                raise urllib.error.URLError(TimeoutError('connect stalled'))
        client.opener=ConnectionTimeout()
    try:yield client,state,recover
    finally:
        state['stop'].set()
        if server:
            server.shutdown();server.server_close();thread.join(timeout=2);assert not thread.is_alive()
        guard.close()

@pytest.mark.parametrize('mode',['connect','headers','body'])
def test_original_refund_automatically_recovers_through_timeout_and_restart(tmp_path,mode):
    with funded_pair(tmp_path/'pair') as p,timeout_endpoint(tmp_path,mode) as (client,remote,recover):
        before=identities(p)
        # Verify transport timeout shape, not a fabricated SwapError label.
        with pytest.raises(SwapError) as error:client('getblockcount')
        cause=error.value.__cause__
        if mode=='connect':
            assert isinstance(cause,urllib.error.URLError) and isinstance(cause.reason,TimeoutError)
        else:assert isinstance(cause,TimeoutError)
        c=wire(p,client);c.tick()
        assert p.state('alice')['stage']=='refund_broadcast'
        p.restart('alice');c=wire(p,client);c.tick()
        assert p.state('alice')['stage']=='refund_broadcast'
        p.a.mine(2);c.tick();assert p.state('alice')['stage']=='refunded'
        p.restart('alice');c=wire(p,client);c.tick()
        assert p.state('alice')['stage']=='refunded'
        recover();assert client('getblockcount')==100;c.tick()
        assert p.state('alice')['stage']=='refunded' and identities(p)==before
        assert len(p.a.records)==1 and not p.b.records and len(p.a.transactions)==2
        assert not p.state('alice')['secret_exposed'] and not p.state('alice')['refs'].get('b')
        assert all(p.nodes[n][0].verify_audit() for n in p.nodes)
        refund=next(o for o in p.nodes['alice'][1].operations(p.sid,private=True) if o['kind']=='refund')
        assert p.a.transactions[refund['txid']]==refund['raw']
        assert all(x=='getblockcount' for x in remote['methods'])

@pytest.mark.parametrize('guard',['immature','incoming','secret','conflicting','reference','script'])
def test_timeout_keeps_original_refund_fences(tmp_path,guard):
    with funded_pair(tmp_path/'pair') as p,timeout_endpoint(tmp_path,'connect') as (client,remote,recover):
        c=wire(p,client);rev,s=c.journal.load(p.sid)
        if guard=='immature':p.a.height-=1
        if guard=='incoming':s['refs']['b']={'txid':'99'*32,'vout':0}
        if guard=='secret':s['secret_exposed']=True
        if guard=='conflicting':s['observations']={'b':{'conflicting':True}}
        if guard=='reference':s['refs']['a']['vout']+=1
        if guard=='script':
            rpc=c.drivers[A].rpc
            def badscript(method,*args):
                value=rpc(method,*args)
                if method=='gettxout':value['scriptPubKey']['hex']='00'
                return value
            c.drivers[A].rpc=badscript
        c._save(p.sid,s,rev);before=identities(p);c.tick()
        assert p.state('alice')['stage']=='funded'
        expected='RECOVERY_CONFLICT' if guard in {'reference','script'} else 'RPC_UNAVAILABLE'
        assert p.state('alice')['last_error']['code']==expected
        assert identities(p)==before and len(p.a.transactions)==1 and not p.b.records

@pytest.mark.parametrize('stage',['wrapped_open','direct_open','read'])
def test_only_transport_timeout_is_classified(stage):
    client=LocalRPC('http://127.0.0.1:1',timeout=1)
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,*args):raise TimeoutError('read stalled')
    class Opener:
        def open(self,*args,**kwargs):
            if stage=='wrapped_open':raise urllib.error.URLError(TimeoutError('connect stalled'))
            if stage=='direct_open':raise TimeoutError('headers stalled')
            return Response()
    client.opener=Opener()
    with pytest.raises(SwapError) as error:client('getblockcount')
    assert type(error.value).__name__=='RPCTransportTimeout'
    assert error.value.as_dict()=={'code':'RPC_UNAVAILABLE','message':'Local chain client request timed out'}

@pytest.mark.parametrize('status',[400,404,500])
def test_http_error_body_timeout_does_not_authorize_refund(tmp_path,status):
    with funded_pair(tmp_path/'pair') as p,timeout_endpoint(tmp_path,'body',status) as (client,remote,recover):
        with pytest.raises(SwapError) as error:client('getblockcount')
        assert type(error.value) is SwapError and error.value.code=='RPC_UNAVAILABLE'
        c=wire(p,client);before=identities(p);c.tick()
        assert p.state('alice')['stage']=='funded' and len(p.a.transactions)==1
        assert identities(p)==before


def test_timeout_outside_transport_is_not_classified():
    client=LocalRPC('http://127.0.0.1:1',timeout=1)
    class Response:
        def __enter__(self):raise TimeoutError('not an open/read timeout')
        def __exit__(self,*args):pass
    class Opener:
        def open(self,*args,**kwargs):return Response()
    client.opener=Opener()
    with pytest.raises(SwapError) as error:client('getblockcount')
    assert type(error.value) is SwapError and error.value.code=='RPC_UNAVAILABLE'
