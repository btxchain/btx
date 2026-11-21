#!/usr/bin/env python3
"""Portable native CLI frontend. JSON is passed on stdin, never through a shell.
No hosted service, private key import, implicit market making or automatic spend.
"""
from __future__ import annotations
import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys

COMMANDS={
 'status':'getswapreadiness','mode':'setswapmode','offers':'listswappublicoffers',
 'request-public':'requestpublicswapquote','quotes':'getswapquotes','preview':'previewswap',
 'confirm':'confirmswap','maker-policy':'setswapmarkets','publish':'publishswapoffer',
 'withdraw':'withdrawswapoffer','invite-create':'createswapinvite','invite-inspect':'inspectswapinvite',
 'invite-connect':'connectswapinvite','receipt-export':'exportswapreceipt','receipt-verify':'verifyswapreceipt',
 'bitcoin-setup':'setupswapbitcoin','asset-policy':'setswapassetpolicy','recovery-export':'exportswaprecovery',
 'swaps':'listswaps','refund':'refundswap','resume':'resumeswap','cancel':'cancelswap'
}
def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('command',choices=COMMANDS);p.add_argument('--cli',default='btx-cli')
 p.add_argument('--datadir',type=Path);p.add_argument('--wallet');p.add_argument('--regtest',action='store_true')
 p.add_argument('--request',type=Path,help='JSON file containing exactly one request object')
 p.add_argument('--output',type=Path,help='Write the result to a new owner-private file')
 args=p.parse_args(argv)
 request={}
 if args.request:
  if args.request.stat().st_size>65536:p.error('request exceeds 64 KiB')
  request=json.loads(args.request.read_text())
  if not isinstance(request,dict):p.error('request must contain one JSON object')
 if args.command=='recovery-export':
  if request:p.error('recovery passphrases are entered interactively, never read from a JSON file')
  first=getpass.getpass('Independent recovery passphrase: ');second=getpass.getpass('Confirm passphrase: ')
  if first!=second or len(first)<20:p.error('passphrases must match and have at least 20 characters')
  request={'passphrase':first};second=''
 command=[args.cli]
 if args.datadir:command.append('-datadir='+str(args.datadir.resolve()))
 if args.wallet:command.append('-rpcwallet='+args.wallet)
 if args.regtest:command.append('-regtest=1')
 command.extend(['-stdin',COMMANDS[args.command]])
 completed=subprocess.run(command,input=json.dumps(request,separators=(',',':'))+'\n',text=True,capture_output=True,timeout=180,check=False)
 request.clear()
 if completed.returncode:
  print(completed.stderr.strip() or 'Native operation failed',file=sys.stderr);return completed.returncode
 if args.output:
  fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'w') as out:out.write(completed.stdout);out.flush();os.fsync(out.fileno())
  print(str(args.output.resolve()))
 else:print(completed.stdout,end='')
 return 0
if __name__=='__main__':
 try:raise SystemExit(main())
 except (OSError,ValueError,subprocess.TimeoutExpired) as e:
  print(str(e),file=sys.stderr);raise SystemExit(1)
