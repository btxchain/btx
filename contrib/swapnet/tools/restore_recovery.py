#!/usr/bin/env python3
"""Restore an encrypted SwapNet recovery bundle into an empty SwapNet directory.

Offline only: stop the native node first (doc/swapnet/RECOVERY.md). The
passphrase is read from the terminal, or from the first line of standard
input when that is not a terminal. Nothing is written unless the bundle
authenticates and its database, audit head and vault key check out.
"""
import argparse
import getpass
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from swapnet.canonical import hex32  # noqa: E402
from swapnet.errors import SwapError  # noqa: E402
from swapnet.recovery import restore_bundle  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description='Restore a SwapNet recovery bundle (.snr) into an empty directory.')
    parser.add_argument('--bundle', required=True, help='absolute path of the .snr bundle')
    parser.add_argument('--destination', required=True, help='absolute path of the new, empty <network datadir>/swapnet')
    parser.add_argument('--genesis', required=True, help='the locally verified chain genesis hash (hex)')
    parser.add_argument('--confirm-node-stopped', action='store_true', help='confirm the native node is stopped')
    args = parser.parse_args(argv)
    if not args.confirm_node_stopped:
        parser.error('stop the native node first, then pass --confirm-node-stopped')
    for name in ('bundle', 'destination'):
        if not Path(getattr(args, name)).is_absolute():
            parser.error(f'--{name} must be an absolute path')
    if sys.stdin.isatty():
        passphrase = getpass.getpass('Recovery bundle passphrase: ')
    else:
        passphrase = sys.stdin.readline().rstrip('\r\n')
    try:
        result = restore_bundle(args.bundle, args.destination, passphrase, hex32(args.genesis.lower()))
    except SwapError as e:
        print(json.dumps({'error': e.as_dict()}), file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
