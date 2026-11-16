#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license; see COPYING.
"""Native POSIX regression: a malformed governor permit cannot enable preservation.

Uses two disposable btx-modeld processes with authenticated loopback PQ1 and tiny
public test models. Requires a PQ1-capable helper. Never uses a wallet or btxd.
The same test is run unchanged on baseline and candidate helpers.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time


def rpc(path, method, params=None):
    request = {'jsonrpc': '1.0', 'id': 'governor-test', 'method': method, 'params': params or []}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(30 if method == 'importmodel' else 5)
        connection.connect(str(path))
        connection.sendall((json.dumps(request) + '\n').encode())
        connection.shutdown(socket.SHUT_WR)
        parts = []
        size = 0
        while True:
            block = connection.recv(65536)
            if not block:
                break
            size += len(block)
            if size > 8 * 1024 * 1024:
                raise RuntimeError('Unexpected oversized fixture RPC reply')
            parts.append(block)
    response = json.loads(b''.join(parts))
    if response.get('error') is not None:
        raise RuntimeError(f'{method}: {response["error"]}')
    return response['result']


def wait_for(read, ready, label, seconds=35):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = read()
        if ready(value):
            return value
        time.sleep(0.2)
    raise RuntimeError(f'Timeout: {label}')


def write_permit(directory, text):
    temporary = directory / 'governor-permit.test-tmp'
    temporary.write_text(text)
    temporary.replace(directory / 'governor-permit.json')


def run(helper, output):
    result = {'helper_sha256': hashlib.sha256(helper.read_bytes()).hexdigest(),
              'scope': 'Native POSIX strict-PQ1 rare preservation; tiny local public models',
              'failures': [], 'status': 'INCOMPLETE', 'processes': [], 'controls': {}}
    processes = []
    logs = []
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='btx-gov-', dir='/tmp') as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        provider, receiver = root / 'provider', root / 'receiver'
        provider.mkdir(mode=0o700)
        receiver.mkdir(mode=0o700)
        permit = json.dumps({'schema_version': 1, 'seeding_allowed': True, 'upload_bps': 1048576,
                             'preservation_allowed': False})
        write_permit(provider, permit)
        write_permit(receiver, permit)
        def termination_requested(_signal, _frame):
            raise RuntimeError('Fixture termination requested; cleaning owned helpers')
        previous_term = signal.signal(signal.SIGTERM, termination_requested)
        try:
            def start(name, directory, extra):
                log = (root / (name + '.log')).open('wb')
                logs.append((name, log))
                args = [str(helper), f'-modeldir={directory}', '-modelstorage=64MiB',
                        f'-modelrpcsocket={directory / "rpc.sock"}', '-pwcchain=regtest',
                        '-modelnatpmp=0', '-modellandiscovery=0', '-modelfollowpeers=0',
                        '-modelseed=auto'] + extra
                process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                processes.append((name, process))
                result['processes'].append({'name': name, 'pid': process.pid, 'args': args})
                path = directory / 'rpc.sock'
                def probe():
                    if process.poll() is not None:
                        raise RuntimeError(f'{name} exited before readiness: {process.returncode}')
                    try:
                        return rpc(path, 'getmodelpeers')
                    except (OSError, json.JSONDecodeError):
                        return None
                wait_for(probe, lambda value: value is not None, name + ' readiness')
                return path

            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            provider_rpc = start('provider', provider,
                                 [f'-modelbind=127.0.0.1:{port}', '-modelhost=1', '-modelpreserverare=0'])

            def import_tiny(tag):
                source = root / ('source-' + tag)
                source.mkdir()
                header = json.dumps({'__metadata__': {'fixture': tag}, 'tensor': {'dtype': 'F32', 'shape': [1], 'data_offsets': [0, 4]}}, separators=(',', ':')).encode()
                header += b' ' * ((-len(header)) % 8)
                body = struct.pack('<Q', len(header)) + header + struct.pack('<f', {'first': 1.0, 'second': 2.0, 'third': 3.0}[tag])
                (source / 'model.safetensors').write_bytes(body)
                imported = rpc(provider_rpc, 'importmodel', [str(source), {'publish': False, 'pin': True}])
                seeded = rpc(provider_rpc, 'seedmodel', [imported['model_id']])
                if seeded.get('seeded') is not True:
                    raise RuntimeError('Provider did not seed exact fixture model')
                return imported, body

            first, first_bytes = import_tiny('first')
            receiver_rpc = start('receiver', receiver,
                                 [f'-modelpeer=127.0.0.1:{port}', '-modelpreserverare=1'])
            model = first['model_id']

            def snapshot():
                if any(p.poll() is not None for _, p in processes):
                    raise RuntimeError('A helper exited during the test')
                return {'participation': rpc(receiver_rpc, 'getmodelpeers')['native_participation'],
                        'models': rpc(receiver_rpc, 'listmodels')['models'],
                        'jobs': rpc(receiver_rpc, 'getmodeljob')['jobs']}

            def observed_twice(after=0):
                timestamps = set()
                def read():
                    state = snapshot()
                    peers = state['participation']['peer_observations']
                    for peer in peers:
                        if (peer['endpoint'] == f'127.0.0.1:{port}' and
                            model in peer['advertised_models'] and
                            len(peer['transport_pin']) == 96 and peer['observed_at_ms'] > after):
                            timestamps.add(peer['observed_at_ms'])
                    return state
                state = wait_for(read, lambda _: len(timestamps) >= 2,
                                 'two fresh authenticated candidate observations')
                return state, max(timestamps)

            def absent(state, previous_count=0):
                return (not any(m['model_id'] == model for m in state['models']) and
                        not any(j['model_id'] == model for j in state['jobs']) and
                        state['participation']['acquired_models'] == previous_count)

            def recovered(expected, body, minimum_count):
                def complete(state):
                    return (state['participation']['acquired_models'] >= minimum_count and any(m['model_id'] == expected['model_id'] and m.get('bytes_verified') is True
                                and not m.get('incomplete', False) for m in state['models']) and
                            any(j['model_id'] == expected['model_id'] and j['status'] == 'done'
                                and j.get('result', {}).get('status') == 'retrieved' for j in state['jobs']))
                state = wait_for(snapshot, complete, 'verified automatic recovery', seconds=45)
                piece = receiver / 'store/artifacts' / expected['artifact_id'] / '0/0.piece'
                if piece.read_bytes() != body:
                    raise RuntimeError('Recovered fixture bytes differ')
                return {'passed': True, 'model_id': expected['model_id'],
                        'artifact_id': expected['artifact_id'], 'piece_sha384': hashlib.sha384(body).hexdigest(),
                        'snapshot': state}


            paused, timestamp = observed_twice()
            result['controls']['valid_pause'] = {'passed': absent(paused), 'snapshot': paused}
            if not absent(paused):
                raise RuntimeError('Valid pause control did not prevent acquisition')
            write_permit(receiver, '{')
            malformed, timestamp = observed_twice(timestamp)
            refused = absent(malformed)
            result['controls']['malformed_pause'] = {'passed': refused, 'snapshot': malformed}
            if not refused:
                result['failures'].append('malformed_permit_enabled_preservation')
                result['controls']['baseline_malformed_completion'] = recovered(first, first_bytes, 1)

            # Test a separate I/O failure against a new model, so baseline's
            # first unwanted acquisition cannot mask this second boundary.
            write_permit(receiver, permit)
            previous_count = snapshot()['participation']['acquired_models']
            second, second_bytes = import_tiny('second')
            if second['model_id'] == model:
                raise RuntimeError('I/O control must use a distinct model')
            model = second['model_id']
            paused_again, timestamp = observed_twice(timestamp)
            result['controls']['valid_pause_second_model'] = {'passed': absent(paused_again, previous_count),
                                                              'snapshot': paused_again}
            if not absent(paused_again, previous_count):
                raise RuntimeError('Second valid pause control did not prevent acquisition')
            # Atomic replacement by a symlink to a private directory makes the
            # permit present but unreadable as file data, even under root. There
            # is no absent-path interval or need to change user privileges.
            unreadable = receiver / 'permit-read-error'
            unreadable.mkdir()
            link = receiver / 'governor-permit.test-tmp'
            link.symlink_to(unreadable.name)
            link.replace(receiver / 'governor-permit.json')
            try:
                (receiver / 'governor-permit.json').read_bytes()
            except OSError as error:
                if error.errno != errno.EISDIR:
                    raise
            else:
                raise RuntimeError('Unreadable permit control did not reach EISDIR')
            io_state, _ = observed_twice(timestamp)
            io_refused = absent(io_state, previous_count)
            result['controls']['unreadable_pause'] = {'passed': io_refused, 'fixture_errno': errno.EISDIR,
                                                      'snapshot': io_state}
            if not io_refused:
                result['failures'].append('unreadable_permit_enabled_preservation')
                result['controls']['baseline_unreadable_completion'] = recovered(second, second_bytes, 2)
            write_permit(receiver, json.dumps({'schema_version': 1, 'seeding_allowed': True, 'upload_bps': 1048576,
                                               'preservation_allowed': True}))
            result['controls']['same_first_model_recovery'] = recovered(first, first_bytes, 1)
            result['controls']['same_second_model_recovery'] = recovered(second, second_bytes, 2)
            # Both original model jobs may already be complete on the
            # failing baseline. A third distinct model proves NEW enabled work.
            before_third = wait_for(snapshot, lambda state: state['participation']['acquired_models'] >= 2, 'completed original-model accounting')
            third, third_bytes = import_tiny('third')
            if any(m['model_id'] == third['model_id'] for m in before_third['models']):
                raise RuntimeError('Fresh candidate already existed before provider import')
            count_before = before_third['participation']['acquired_models']
            if count_before != 2:
                raise RuntimeError('First two model completions were not accounted exactly once')
            fresh = recovered(third, third_bytes, 3)
            if fresh['snapshot']['participation']['acquired_models'] != count_before + 1:
                raise RuntimeError('Fresh acquisition did not increment accounting exactly once')
            fresh['absent_before_provider_import'] = True
            fresh['acquired_before'] = count_before
            result['controls']['fresh_enabled_acquisition'] = fresh
            final = snapshot()
            if final['participation']['acquired_models'] != 3:
                raise RuntimeError('Unexpected automatic acquisition accounting')
            result['status'] = 'FAIL' if result['failures'] else 'PASS'
        except Exception as error:
            result['error'] = repr(error)
            result['status'] = 'INCOMPLETE'
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            cleanup_errors = []
            for name, process in reversed(processes):
                try:
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        cleanup_errors.append(name + ': graceful shutdown timed out')
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=10)
                    result.setdefault('shutdown', {})[name] = process.returncode
                    if process.returncode != 0:
                        cleanup_errors.append(name + ': nonzero shutdown ' + str(process.returncode))
                except Exception as error:
                    cleanup_errors.append(name + ': ' + repr(error))
            for name, stream in logs:
                try:
                    stream.close()
                    (output.parent / (output.stem + '-' + name + '.log')).write_bytes((root / (name + '.log')).read_bytes())
                except Exception as error:
                    cleanup_errors.append(name + ' log: ' + repr(error))
            result['cleanup_errors'] = cleanup_errors
            result['clean_shutdown'] = not cleanup_errors and all(p.poll() is not None for _, p in processes)
            if not result['clean_shutdown']:
                result['status'] = 'INCOMPLETE'
            signal.signal(signal.SIGTERM, previous_term)
    result['private_runtime_removed'] = not root.exists()
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result.get(k) for k in ['status', 'failures', 'error', 'clean_shutdown']}))
    return 0 if result['status'] == 'PASS' else 1 if result['status'] == 'FAIL' else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'posix':
        parser.error('Requires the native POSIX helper RPC transport')
    raise SystemExit(run(args.helper.resolve(), args.output.resolve()))
