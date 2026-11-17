#!/usr/bin/env python3
"""Human-oriented native RPC client. No hosted service, signing key, or network bypass."""
import argparse
from decimal import Decimal, InvalidOperation
import json
import os
import re
import subprocess
import sys

def rpc(binary,wallet,method,body):
 command=[binary]+(['-rpcwallet='+wallet] if wallet else [])+[method,json.dumps(body,separators=(',',':'),allow_nan=False)]
 p=subprocess.run(command,text=True,capture_output=True,timeout=90)
 if p.returncode:raise RuntimeError(p.stderr.strip() or p.stdout.strip() or 'btx-cli failed')
 return json.loads(p.stdout)
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--cli',default=os.environ.get('BTX_CLI','btx-cli'));p.add_argument('--wallet',default='')
 commands=p.add_subparsers(dest='command',required=True)
 commands.add_parser('status');commands.add_parser('pause')
 m=commands.add_parser('mode');m.add_argument('mode',choices=['observe','trade','maker','recovery'])
 q=commands.add_parser('quote');q.add_argument('--sell',required=True);q.add_argument('--buy',required=True);q.add_argument('--atoms',required=True)
 l=commands.add_parser('quotes');l.add_argument('request_id')
 v=commands.add_parser('preview');v.add_argument('quote_id');v.add_argument('--fee-cap-atoms',required=True)
 c=commands.add_parser('confirm');c.add_argument('preview_id');c.add_argument('--confirm',action='store_true');g=c.add_mutually_exclusive_group(required=True);g.add_argument('--mandate-id');g.add_argument('--single-trade-mandate',action='store_true')
 s=commands.add_parser('swap');s.add_argument('swap_id')
 e=commands.add_parser('receipt');e.add_argument('swap_id');e.add_argument('--consent-to-disclose',action='store_true')
 args=p.parse_args()
 if args.command=='status':method,body='getswaponboarding',{}
 elif args.command=='pause':method,body='setswapmode',{'mode':'recovery'}
 elif args.command=='mode':method,body='setswapmode',{'mode':args.mode}
 elif args.command=='quote':
  if not re.fullmatch(r'[1-9][0-9]{0,77}',args.atoms):p.error('Use a positive canonical integer number of atomic units')
  method,body='requestswapquote',{'sell_asset':args.sell,'buy_asset':args.buy,'sell_atoms':args.atoms}
 elif args.command=='quotes':method,body='getswapquotes',{'request_id':args.request_id}
 elif args.command=='preview':method,body='previewswapquote',{'quote_id':args.quote_id,'max_local_fee_atoms':args.fee_cap_atoms}
 elif args.command=='confirm':
  if not args.confirm:p.error('Explicit --confirm is required; inspect the preview first')
  body={'preview_id':args.preview_id,'consent':True,'create_single_trade_mandate':args.single_trade_mandate}
  if args.mandate_id:body['mandate_id']=args.mandate_id
  method='confirmswapquote'
 elif args.command=='swap':method,body='getswap',{'swap_id':args.swap_id}
 else:
  if not args.consent_to_disclose:p.error('Receipt export links public counterparties and chain transactions; explicit consent required')
  method,body='exportswapreceipt',{'swap_id':args.swap_id,'consent':True}
 try:print(json.dumps(rpc(args.cli,args.wallet,method,body),indent=2))
 except (ValueError,RuntimeError,OSError,subprocess.TimeoutExpired) as exc:
  print(f'ERROR: {exc}\nA timeout does not prove that a trade failed. Inspect its saved preview/swap ID before retrying.',file=sys.stderr);return 1
 return 0
if __name__=='__main__':raise SystemExit(main())
