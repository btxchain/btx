#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Real-helper cloud responsiveness regression, disposable data and loopback only.

Run: python3 test_modelnet_cloud_responsiveness.py --helper /path/to/btx-modeld --out NEW_DIR
Set BTX_OPENSSL to the matching PQ1-capable OpenSSL executable.
Exit 0: contract passes; 2: reproduced responsiveness defect; 1: setup/control failure.
No node, wallet, real cloud credentials, peers or inference is used.
"""
import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time
import traceback
from urllib.parse import urlsplit

SIZE = 256 * 1024
HOLD_SECONDS = 2
RPC_TIMEOUT = 10


def payload():
    header = json.dumps({'w': {'dtype': 'U8', 'shape': [SIZE-128], 'data_offsets': [0, SIZE-128]}}, separators=(',', ':')).encode()
    assert len(header) <= 120
    return struct.pack('<Q', 120) + header.ljust(120, b' ') + b'A' * (SIZE-128)


class Origin:
    """Small controlled HTTP response fixture, not AWS/MinIO or SigV4 verification."""
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.objects = {}
        self.requests = []
        self.gate = {}
        self.handler_threads = []
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def setup(self):
                super().setup(); self.connection.settimeout(8)
            def handle_request(self):
                owner.handler_threads.append(threading.current_thread())
                row = {'method': self.command, 'path': urlsplit(self.path).path}
                owner.requests.append(row)
                try:
                    self.connection.settimeout(8)
                    path = row['path']
                    if self.command == 'PUT':
                        length = int(self.headers.get('Content-Length', '0'))
                        assert 0 <= length <= SIZE and len(owner.requests) <= 16
                        data = self.rfile.read(length)
                        assert len(data) == length
                        if '/files/' in path and not owner.entered.is_set():
                            owner.gate.update(entered=time.monotonic(), path=path, bytes=length)
                            owner.entered.set()
                            assert owner.release.wait(8), 'origin watchdog expired'
                            owner.gate['resumed'] = time.monotonic()
                        owner.objects[path] = data
                        body = b''
                    else:
                        assert self.command == 'GET' and path in owner.objects
                        body = owner.objects[path]
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.send_header('ETag', '"' + hashlib.md5(owner.objects[path]).hexdigest() + '"')
                    self.end_headers()
                    if body: self.wfile.write(body)
                    row['status'] = 200
                except Exception:
                    row['error'] = traceback.format_exc()
                    self.send_error(500)
            do_PUT = handle_request
            do_GET = handle_request
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = False
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        self.endpoint = 'http://127.0.0.1:' + str(self.server.server_port)

    def __enter__(self): self.thread.start(); return self
    def unblock(self): self.gate.setdefault('released', time.monotonic()); self.release.set()
    def __exit__(self, *args):
        self.unblock(); self.server.shutdown(); self.server.server_close(); self.thread.join(2)
        assert not self.thread.is_alive()
        assert not any(t.is_alive() for t in self.handler_threads)


class Helper:
    def __init__(self, binary, root, out):
        self.binary, self.root, self.out = binary, root, out
        self.model = root / 'model'; self.model.mkdir()
        self.endpoint = root / 'rpc.sock'; self.calls = []; self.exits = []; self.seq = 0; self.mu = threading.Lock()

    def rpc(self, method, *params):
        with self.mu:
            self.seq += 1; ident = self.seq
            row = {'id': ident, 'method': method, 'sent': time.monotonic()}; self.calls.append(row)
        try:
            with socket.socket(socket.AF_UNIX) as conn:
                conn.settimeout(RPC_TIMEOUT); conn.connect(str(self.endpoint))
                conn.sendall(json.dumps({'id': ident, 'method': method, 'params': list(params)}).encode()+b'\n')
                conn.shutdown(socket.SHUT_WR)
                with conn.makefile('rb') as wire: raw = wire.readline(2*1024*1024)
            row['finished'] = time.monotonic(); row['raw'] = raw.decode(errors='replace')
            assert raw.endswith(b'\n')
            reply = json.loads(raw); assert reply['id'] == ident
            row['reply'] = reply
            return reply
        except Exception:
            row['error'] = traceback.format_exc(); raise

    def ok(self, method, *params):
        r = self.rpc(method, *params); assert r.get('error') is None, r
        return r['result']

    @contextmanager
    def running(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith(('BTX_', 'DYLD_', 'BITCOIN_'))}
        if 'BTX_OPENSSL' in os.environ: env['BTX_OPENSSL'] = os.environ['BTX_OPENSSL']
        with (self.out / ('helper-' + str(len(self.exits)) + '.log')).open('wb') as log:
            proc = subprocess.Popen([str(self.binary), '-modeldir='+str(self.model), '-modelrpcsocket='+str(self.endpoint),
                                     '-modelstorage=64MiB', '-modelbind=off', '-modellandiscovery=0', '-modelnatpmp=0',
                                     '-modelfollowpeers=0', '-modelseed=off', '-modelpreserverare=0'], cwd=self.root, env=env,
                                    stdout=log, stderr=subprocess.STDOUT)
            try:
                until = time.monotonic()+30
                while True:
                    assert proc.poll() is None and time.monotonic()<until, 'helper startup failed'
                    try: self.ok('hello'); break
                    except (FileNotFoundError, ConnectionRefusedError): time.sleep(.05)
                yield
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try: proc.wait(15)
                    except subprocess.TimeoutExpired:
                        proc.kill(); proc.wait(5); raise AssertionError('helper shutdown timeout')
                self.exits.append(proc.returncode); assert proc.returncode == 0


def budget(info):
    return {k: info[k] for k in ('budget_used_gets', 'origin_bytes', 'budget_used_gets_day',
                                'budget_used_gets_month', 'budget_used_bytes_day', 'budget_used_bytes_month')}


def run(binary, out):
    r = {'complete': False, 'violations': [], 'helper_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    f = origin = None; started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='s2-cloud-') as td:
            root = Path(td); source = root/'model.safetensors'; source.write_bytes(payload())
            f = Helper(binary, root, out)
            with Origin() as origin:
                creds = root/'credentials'; creds.write_text('aws_access_key_id=TEST_KEY_NOT_REAL\naws_secret_access_key=TEST_SECRET_NOT_REAL\n'); creds.chmod(0o600)
                cfg = {'endpoint': origin.endpoint, 'bucket': 'fixture', 'prefix': 'original', 'region': 'us-east-1',
                       'layout': 'SOURCE_FILES', 'provider': 'GENERIC_S3', 'credential_ref': str(creds),
                       'credential_ref_kind': 'path', 'use_fake': False, 'allow_http_loopback': True,
                       'budget_gets': 4, 'budget_origin_bytes': 4*SIZE, 'automatic_spend_atoms': 0,
                       'idempotency_key': 'configure'}
                replacement = dict(cfg, prefix='replacement', idempotency_key='busy-then-retry')
                with f.running():
                    assert f.ok('setcloudstorage', cfg)['applied']
                    assert f.ok('testcloudstorage')['probe_ok']
                    before = f.ok('getcloudstorageinfo'); before_budget = budget(before)
                    assert before_budget['budget_used_gets'] == 1 and before_budget['origin_bytes'] == len(b'btx-cloud-probe')
                    config_bytes = (f.model/'cloud.json').read_bytes(); budget_bytes = (f.model/'cloud-budget.json').read_bytes()
                    info = f.ok('getmodelnetworkinfo'); assert info['unix_workers']==2 and info['pq1_ready']
                    r['initial_info'] = info
                    upload = {}
                    def put():
                        try: upload['reply'] = f.ok('importmodel', str(source), {'pin': True, 'publish': False})
                        except Exception: upload['error'] = traceback.format_exc()
                    thread = threading.Thread(target=put, daemon=True); timer = None; thread.start()
                    try:
                        assert origin.entered.wait(5), 'source PUT not reached'
                        timer = threading.Timer(HOLD_SECONDS+.05, origin.unblock); timer.start()
                        f.ok('hello'); hello = dict(f.calls[-1]); r['paused_hello'] = hello
                        if hello['finished'] >= origin.gate.get('released', float('inf')):
                            r['violations'].append('hello waited for upload release')
                        if not origin.release.is_set():
                            state = f.ok('getmodelnetworkinfo'); r['paused_info'] = state
                            if origin.release.is_set(): r['violations'].append('status waited for upload release')
                            else:
                                assert state['helper_ready'] and state['cloud_storage_busy'] is True
                                assert 'cloud_storage' not in state and state['delivery']['direct_file_seed'] is False
                                assert state['delivery']['origin_file_complete'] is False
                                assert 'origin_diversity' not in state and 'cloud_amplification' not in state
                                for method, params in [('getcloudstorageinfo', ()), ('setcloudstorage', (replacement,)),
                                                       ('setmodelstoragepolicy', ({'idempotency_key':'busy-policy'},)),
                                                       ('removemodelstorage', ({'mode':'DETACH'},))]:
                                    reply = f.rpc(method, *params)
                                    assert not origin.release.is_set(), method+' did not refuse promptly'
                                    assert reply.get('error', {}).get('code') == 'HELPER_BUSY', reply
                                r['busy_controls'] = True
                                assert (f.model/'cloud.json').read_bytes() == config_bytes
                                assert (f.model/'cloud-budget.json').read_bytes() == budget_bytes
                        if not r.get('busy_controls'): r['violations'].append('busy controls not reached before release')
                    finally:
                        if timer: timer.join(4)
                        origin.unblock(); thread.join(RPC_TIMEOUT+1)
                        assert not thread.is_alive() and (timer is None or not timer.is_alive())
                    assert 'error' not in upload, upload
                    reply = upload['reply']; assert reply['cloud_uploaded'] is True
                    key = '/fixture/'+reply['cloud_files'][0]['object_key']; assert origin.objects[key] == payload()
                    assert (f.model/'cloud.json').read_bytes() == config_bytes
                    assert (f.model/'cloud-budget.json').read_bytes() == budget_bytes
                    assert budget(f.ok('getcloudstorageinfo')) == before_budget
                    # The same key rejected during upload must work after release,
                    # and a replay must not change persisted accounting/config.
                    assert f.ok('setcloudstorage', replacement)['applied']
                    after_config = (f.model/'cloud.json').read_bytes()
                    assert f.ok('setcloudstorage', replacement)['applied']
                    assert (f.model/'cloud.json').read_bytes() == after_config
                    assert budget(f.ok('getcloudstorageinfo')) == before_budget
                    assert f.ok('setmodelstoragepolicy', {'idempotency_key':'busy-policy'})['policy_applied']
                    assert f.ok('setmodelstoragepolicy', {'idempotency_key':'busy-policy'})['policy_applied']
                    again = f.ok('importmodel', str(source), {'pin': True, 'publish': False})
                    assert again['cloud_uploaded'] and again['artifact_id']==reply['artifact_id']
                    assert origin.objects['/fixture/'+again['cloud_files'][0]['object_key']] == payload()
                    assert f.ok('testcloudstorage')['probe_ok']
                    final_budget = budget(f.ok('getcloudstorageinfo'))
                    assert final_budget['budget_used_gets']==2 and final_budget['origin_bytes']==2*len(b'btx-cloud-probe')
                    r.update(upload_bytes=SIZE, upload_sha256=hashlib.sha256(payload()).hexdigest(), before_budget=before_budget,
                             final_budget=final_budget, same_key_retry=True, duplicate_replay=True, upload_retry=True)
                    assert f.ok('hello')['suite']=='pq1'
                with f.running():
                    state = f.ok('getcloudstorageinfo')
                    assert state['prefix']=='replacement' and state['automatic_spend_atoms']==0
                    assert budget(state)==final_budget and (f.model/'cloud.json').read_bytes()==after_config
                    info = f.ok('getmodelnetworkinfo')
                    assert info['helper_ready'] and not info.get('cloud_storage_busy', False)
                    assert info['cloud_storage']['configured']
                    r['restart_preserves_configuration_and_budget'] = True
                r['origin_objects'] = {k: {'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for k,v in origin.objects.items()}
                assert not any('error' in x for x in origin.requests), origin.requests
            r['complete'] = True
    except Exception: r['error'] = traceback.format_exc()
    finally:
        if f: r.update(calls=f.calls, exits=f.exits)
        if origin: r.update(gate=origin.gate, origin_requests=origin.requests, origin_handlers_alive=sum(t.is_alive() for t in origin.handler_threads))
        r['seconds'] = time.monotonic()-started
        r['verdict'] = 'SETUP_OR_CONTROL_FAILURE' if not r['complete'] else ('REPRODUCED' if r['violations'] else 'PASS')
        (out/'result.json').write_text(json.dumps(r,indent=2)+'\n')
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--helper',type=Path,required=True); ap.add_argument('--out',type=Path,required=True)
    a = ap.parse_args(); a.out.mkdir(parents=True,exist_ok=False)
    r = run(a.helper.resolve(), a.out); print(json.dumps({'verdict':r['verdict'],'violations':r['violations'],'seconds':r['seconds']}))
    return 1 if not r['complete'] else (2 if r['violations'] else 0)

if __name__=='__main__': raise SystemExit(main())
