#!/usr/bin/env python3
"""Fail closed unless all required acceptance records include scoped evidence.
This is an evidence-presence gate, not cryptographic validation of the evidence.
"""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
REQUIRED=['source_inventory','cargo_lock_review','rust_core_tests','native_linux','native_windows','native_macos','live_regtest_wallet','qt_parity','native_ipc_adversarial','native_csp','webgl_worker','accessibility','installer_signing','windows_acl','hardware_signer','local_llm','resource_profile']
def evaluate(document):
 entries={x.get('id'):x for x in document.get('checks',[])}
 return [k for k in REQUIRED if not (entries.get(k,{}).get('status')=='PASS' and entries[k].get('evidence') and entries[k].get('source_sha')==document.get('source_sha'))]
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);a=p.parse_args();d=json.loads(a.report.read_text());missing=evaluate(d)
 print(json.dumps({'qualified':not missing,'missing_or_unproven':missing,'scope':'Manifest consistency only; reviewer must authenticate test evidence'},indent=2));raise SystemExit(bool(missing))
