#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import argparse
import json
import sys
import hashlib

def enumerate(args):
    sys.stdout.write(json.dumps([
        {
            "fingerprint": "00000001",
            "type": "trezor",
            "model": "trezor_t",
            "capabilities": {
                "p2mr": True,
                "pq_algorithms": ["slh_dsa_128s"],
            },
        },
        {
            "fingerprint": "00000002",
            "type": "trezor",
            "model": "trezor_one",
            "capabilities": {
                "p2mr": True,
                "pq_algorithms": ["slh_dsa_128s"],
            },
        },
    ]))


def getdescriptors(args):
    tpub_1 = "tpubDCBEcmVKbfC9KfdydyLbJ2gfNL88grZu1XcWSW9ytTM6fitvaRmVyr8Ddf7SjZ2ZfMx9RicjYAXhuh3fmLiVLPodPEqnQQURUfrBKiiVZc8"
    tpub_2 = "tpubDDAfvogaaAxaFJ6c15ht7Tq6ZmiqFYfrSmZsHu7tHXBgnjMZSHAeHSwhvjARNA6Qybon4ksPksjRbPDVp7yXA1KjTjSd5x18KHqbppnXP1s"
    if args.fingerprint == "00000001":
        receive = f"mr(pk_slh([00000001/87h/1h/0h]{tpub_1}/0/*))"
        internal = f"mr(pk_slh([00000001/87h/1h/0h]{tpub_1}/1/*))"
    elif args.fingerprint == "00000002":
        receive = f"mr(pk_slh([00000002/87h/1h/0h]{tpub_2}/0/*))"
        internal = f"mr(pk_slh([00000002/87h/1h/0h]{tpub_2}/1/*))"
    else:
        sys.stdout.write(json.dumps({"error": "Unexpected fingerprint", "fingerprint": args.fingerprint}))
        return

    sys.stdout.write(json.dumps({
        "receive": [receive],
        "internal": [internal],
    }))


def getp2mrpubkeys(args):
    if args.fingerprint not in {"00000001", "00000002"}:
        sys.stdout.write(json.dumps({"error": "Unexpected fingerprint", "fingerprint": args.fingerprint}))
        return
    if args.desc is None or args.index is None:
        sys.stdout.write(json.dumps({"error": "Missing descriptor/index"}))
        return

    material = f"{args.fingerprint}|{args.desc}|{args.index}|slh_dsa_128s".encode("utf-8")
    pubkey = hashlib.sha256(material).hexdigest()
    sys.stdout.write(json.dumps({
        "entries": [
            {
                "expr_index": 0,
                "algo": "slh_dsa_128s",
                "pubkey": pubkey,
            }
        ]
    }))

parser = argparse.ArgumentParser(prog='./multi_signers.py', description='External multi-signer mock')
parser.add_argument('--fingerprint')
parser.add_argument('--chain', default='main')
parser.add_argument('--stdin', action='store_true')

subparsers = parser.add_subparsers(description='Commands', dest='command')
subparsers.required = True

parser_enumerate = subparsers.add_parser('enumerate', help='list available signers')
parser_enumerate.set_defaults(func=enumerate)

parser_getdescriptors = subparsers.add_parser('getdescriptors')
parser_getdescriptors.set_defaults(func=getdescriptors)
parser_getdescriptors.add_argument('--account', metavar='account')

parser_getp2mrpubkeys = subparsers.add_parser('getp2mrpubkeys')
parser_getp2mrpubkeys.set_defaults(func=getp2mrpubkeys)
parser_getp2mrpubkeys.add_argument('--desc', metavar='desc')
parser_getp2mrpubkeys.add_argument('--index', metavar='index')


if not sys.stdin.isatty():
    buffer = sys.stdin.read()
    if buffer and buffer.rstrip() != "":
        sys.argv.extend(buffer.rstrip().split(" "))

args = parser.parse_args()

args.func(args)
