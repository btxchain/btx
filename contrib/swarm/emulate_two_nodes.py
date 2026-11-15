#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Two processes on this machine emulate two ranks.

A CUDA device is used when this interpreter can see one. One device is not
two devices. Two processes are not two physical hosts. Without CUDA the
process exits 2 and moves no tensors.
"""

import socket
import struct
import sys
import time
from multiprocessing import get_context


def exchange(rank, port, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if rank == 0:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.listen(1)
            peer, addr = sock.accept()
            if addr[0] != "127.0.0.1":
                raise RuntimeError("PEER")
            peer.sendall(struct.pack("!I", len(payload)) + payload)
            header = peer.recv(4)
            (n,) = struct.unpack("!I", header)
            got = b""
            while len(got) < n:
                chunk = peer.recv(n - len(got))
                if not chunk:
                    raise RuntimeError("SHORT")
                got += chunk
            peer.close()
            return got
        for _ in range(400):
            try:
                sock.connect(("127.0.0.1", port))
                break
            except ConnectionRefusedError:
                time.sleep(0.05)
        else:
            raise RuntimeError("NO_ROUTE")
        header = sock.recv(4)
        (n,) = struct.unpack("!I", header)
        got = b""
        while len(got) < n:
            chunk = sock.recv(n - len(got))
            if not chunk:
                raise RuntimeError("SHORT")
            got += chunk
        sock.sendall(struct.pack("!I", len(payload)) + payload)
        return got
    finally:
        sock.close()


def rank_main(rank, port, out):
    try:
        import torch
    except Exception as exc:
        out.put({"rank": rank, "ok": False, "err": "ENGINE_ABSENT", "detail": type(exc).__name__})
        return
    if not torch.cuda.is_available():
        out.put({"rank": rank, "ok": False, "err": "ENGINE_ABSENT"})
        return
    devices = torch.cuda.device_count()
    if devices != 1:
        out.put({"rank": rank, "ok": False, "err": "DEVICE_COUNT", "devices": devices})
        return
    torch.manual_seed(35 + rank)
    device = torch.device("cuda")
    layer = torch.nn.Linear(16, 1).to(device)
    start = layer.weight.detach().clone()
    x = torch.randn(64, 16, device=device)
    y = torch.randn(64, 1, device=device)
    opt = torch.optim.SGD(layer.parameters(), lr=0.05)
    loss0 = None
    loss1 = None
    for step in range(5):
        opt.zero_grad()
        loss = torch.nn.functional.mse_loss(layer(x), y)
        if step == 0:
            loss0 = float(loss.detach())
        loss.backward()
        opt.step()
        loss1 = float(loss.detach())
    page = torch.arange(1024, device=device, dtype=torch.float32)
    copy = torch.empty_like(page)
    copy.copy_(page)
    payload = layer.weight.detach().contiguous().view(-1).cpu().numpy().tobytes()
    got = exchange(rank, port, payload)
    out.put(
        {
            "rank": rank,
            "ok": True,
            "loss0": loss0,
            "loss1": loss1,
            "weight_changed": not torch.equal(start, layer.weight.detach()),
            "copy_equal": bool(torch.equal(page, copy)),
            "copy_bytes": int(page.numel() * page.element_size()),
            "sent": len(payload),
            "got": len(got),
            "devices": devices,
            "name": torch.cuda.get_device_name(0),
        }
    )


def main():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    ctx = get_context("spawn")
    out = ctx.Queue()
    first = ctx.Process(target=rank_main, args=(0, port, out))
    first.start()
    time.sleep(0.3)
    second = ctx.Process(target=rank_main, args=(1, port, out))
    second.start()
    first.join(120)
    second.join(120)
    rows = [out.get(timeout=5), out.get(timeout=5)]
    rows.sort(key=lambda row: row["rank"])
    print("HOSTS 1")
    print("RANKS 2")
    print("PROCESSES 2")
    for row in rows:
        print(
            "RANK",
            row["rank"],
            "OK",
            int(row.get("ok", False)),
            "ERR",
            row.get("err", ""),
            "LOSS0",
            row.get("loss0", ""),
            "LOSS1",
            row.get("loss1", ""),
            "CHANGED",
            int(row.get("weight_changed", False)),
            "COPY",
            int(row.get("copy_equal", False)),
            "COPY_BYTES",
            row.get("copy_bytes", 0),
            "SENT",
            row.get("sent", 0),
            "GOT",
            row.get("got", 0),
            "DEVICES",
            row.get("devices", 0),
        )
    if any(not row.get("ok") for row in rows):
        return 2
    if rows[0]["sent"] != rows[1]["got"] or rows[1]["sent"] != rows[0]["got"]:
        print("EXCHANGE MISMATCH")
        return 3
    if rows[0]["devices"] != 1 or not rows[0]["weight_changed"] or not rows[1]["weight_changed"]:
        return 4
    if not rows[0]["copy_equal"] or rows[0]["copy_bytes"] != 4096:
        return 5
    print("GPU_TWO_RANK_ONE_HOST PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
