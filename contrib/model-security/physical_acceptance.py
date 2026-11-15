#!/usr/bin/env python3
"""Read-only enrolled-host health qualification over existing SSH accounts.

Each remote command is pinned and read-only; this tool never enables a service,
issues grants or signs results. Unique OS IDs are weak inventory hints, not
proof of independent hardware or independent administration. Human signoff,
actual model workloads and partition testing are additional requirements.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

HOST = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9_.@-]{0,126}$")


def query(alias: str, command: list[str], timeout: int) -> str:
    if not HOST.fullmatch(alias):
        raise ValueError('Unsafe host alias')
    args = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
            '-o', 'ControlMaster=no', '-o', 'ConnectTimeout=10', '--', alias,
            ' '.join(map(shlex.quote, command))]
    outcome = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                             check=False, env={'PATH': '/usr/bin:/bin'})
    if outcome.returncode != 0 or len(outcome.stdout) > 256000:
        raise RuntimeError(f'remote command refused: exit={outcome.returncode}')
    return outcome.stdout.strip()


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--inventory', type=Path, required=True)
    cli.add_argument('--report', type=Path, required=True)
    args = cli.parse_args()
    inventory = json.loads(args.inventory.read_text())
    hosts = inventory['hosts']
    if not isinstance(hosts, list) or not (3 <= len(hosts) <= 12):
        raise ValueError('Need 3-12 explicitly enrolled host entries')
    seen = set()
    report = {'schema': 'BTX/PhysicalSecurityAcceptance/v1', 'timestamp_ms': int(time.time()*1000),
              'status': 'NOT_QUALIFIED', 'actual_host_interactions_attempted': True,
              'hardware_independence_proven': False, 'independent_operator_review': 'REQUIRED',
              'complete_llm_containment_proven': False, 'hosts': []}
    for item in hosts:
        alias = item['ssh_alias']
        if alias in seen or not HOST.fullmatch(alias):
            raise ValueError('Host aliases must be unique and non-option-form')
        seen.add(alias)
        host = {'ssh_alias': alias, 'status': 'NOT_RUN'}
        try:
            # Hash a locally stable OS identifier to compare accidental duplicate
            # virtual-machine inventories without leaking it to the report.
            identity = query(alias, ['cat','/etc/machine-id'], 25)
            if not re.fullmatch('[0-9a-f]{32}',identity):
                raise RuntimeError('machine-id unavailable or invalid')
            host['machine_id_sha384'] = hashlib.sha384(identity.encode()).hexdigest()
            raw = query(alias, ['btx-cli','modelsecurity',json.dumps({'op': 'status'})],40)
            obj = json.loads(raw)
            mesh = obj.get('multi_host_security',{})
            host.update({'status':'OBSERVED',
                         'journal_valid': obj.get('journal_valid', False),
                         'continuous_protection_required': obj.get('continuous_protection_required', False),
                         'mesh_enabled': mesh.get('enabled', False),
                         'recent_authenticated_peer_sessions':mesh.get('authenticated_recent_peer_sessions',0),
                         'legacy_generatemodel_mediated':obj.get('legacy_generatemodel_mediated',False),
                         'general_gpu_runtime_qualified':obj.get('general_gpu_runtime_qualified',False),
                         'maintenance_error':obj.get('maintenance_error','')})
        except (OSError, subprocess.SubprocessError, ValueError, RuntimeError, KeyError) as e:
            host['status'] = 'FAILED'
            host['error_type'] = type(e).__name__
        report['hosts'].append(host)
    ids = [h.get('machine_id_sha384') for h in report['hosts']]
    report['distinct_machine_ids_observed'] = len(set(ids)) == len(ids) and all(ids)
    success = report['distinct_machine_ids_observed'] and all(
        h['status'] == 'OBSERVED' and h['journal_valid'] and
        h['continuous_protection_required'] and h['mesh_enabled'] and
        h['recent_authenticated_peer_sessions'] >= 2 and not h['maintenance_error']
        for h in report['hosts'])
    report['status'] = 'HOST_STATUS_PRECHECK_PASSED_NOT_DEPLOYMENT_QUALIFIED' if success else 'BLOCKED'
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'status':report['status'],'report':str(args.report)}, indent=2))
    return 0 if success else 2

if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,KeyError,OSError) as e:
        print('BLOCKED:',e,file=sys.stderr);sys.exit(2)
