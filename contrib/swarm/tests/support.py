"""Shared test identities and local-node helpers; no external peers required."""

import asyncio
import socket

from btxmesh.cli import command
from btxmesh.codec import digest


def H(label):
    return digest("BTX/Test/1", label)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


async def wait_leader(nodes, timeout=10):
    async with asyncio.timeout(timeout):
        while True:
            leaders = [node for node in nodes if node.raft.role == "leader"]
            if len(leaders) == 1:
                return leaders[0]
            await asyncio.sleep(0.05)


async def call(node, kind, body):
    # Exercise the authenticated local socket and the normal Raft apply path.
    return await command(node.data, kind, body)
