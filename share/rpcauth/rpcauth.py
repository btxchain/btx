#!/usr/bin/env python3
# Copyright (c) 2015-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hmac
import json
import sys
from argparse import ArgumentParser
from getpass import getpass
from secrets import token_hex, token_urlsafe

def generate_salt(size):
    """Create size byte hex salt"""
    return token_hex(size)

def generate_credential():
    """Create 32 byte urlsafe credential."""
    return token_urlsafe(32)

def generate_password():
    """Backward-compatible alias for the credential generator."""
    return generate_credential()

def credential_to_hmac(salt, credential):
    m = hmac.new(salt.encode('utf-8'), credential.encode('utf-8'), 'SHA256')
    return m.hexdigest()

def password_to_hmac(salt, credential):
    """Backward-compatible alias retained for tests/importers."""
    return credential_to_hmac(salt, credential)

def main():
    parser = ArgumentParser(description='Create login credentials for a JSON-RPC user')
    parser.add_argument('username', help='the username for authentication')
    parser.add_argument('credential', metavar='password', help='leave empty to generate a random credential or specify "-" to prompt for one', nargs='?')
    parser.add_argument("-j", "--json", help="output to json instead of plain-text", action='store_true')
    parser.add_argument('--output', dest='output', help='file to store credentials, to be used with -rpcauthfile')
    args = parser.parse_args()

    if not args.credential:
        args.credential = generate_credential()
    elif args.credential == '-':
        args.credential = getpass()

    # Create 16 byte hex salt
    salt = generate_salt(16)
    credential_hmac = credential_to_hmac(salt, args.credential)
    rpcauth = f'{args.username}:{salt}${credential_hmac}'

    if args.output:
        with open(args.output, "a", encoding="utf8") as outfile:
            outfile.write(rpcauth + "\n")

    if args.json:
        odict = {
            'username': args.username,
            # Preserve the historical JSON surface for external tooling.
            'password': args.credential,
            'credential': args.credential,
        }
        if not args.output:
            odict['rpcauth'] = rpcauth
        json.dump(odict, sys.stdout)
        sys.stdout.write("\n")
    else:
        if not args.output:
            print('String to be appended to btx.conf:')
            print(f'rpcauth={rpcauth}')
        print(f'Generated credential:\n{args.credential}')

if __name__ == '__main__':
    main()
