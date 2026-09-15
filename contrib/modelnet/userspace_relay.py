#!/usr/bin/env python3
"""Opaque TCP splice for connectivity labs B–F (no netns). Bytes are forwarded unchanged so inner PQ1 stays end-to-end."""
from __future__ import annotations

import argparse
import select
import socket
import sys
import threading


def splice(a: socket.socket, b: socket.socket) -> None:
    socks = [a, b]
    try:
        while True:
            r, _, err = select.select(socks, [], socks, 30)
            if err or not r:
                return
            for src in r:
                dst = b if src is a else a
                try:
                    data = src.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    dst.sendall(data)
                except OSError:
                    return
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--listen", required=True, help="host:port")
    p.add_argument("--to", required=True, help="host:port")
    args = p.parse_args()
    lh, lp = args.listen.rsplit(":", 1)
    th, tp = args.to.rsplit(":", 1)
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((lh, int(lp)))
    ls.listen(16)
    print(f"userspace_relay listen {lh}:{lp} -> {th}:{tp}", flush=True)
    while True:
        c, _ = ls.accept()
        d = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            d.connect((th, int(tp)))
        except OSError:
            c.close()
            continue
        threading.Thread(target=splice, args=(c, d), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main() or 0)
