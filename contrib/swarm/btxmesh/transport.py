"""Pinned mutual TLS between configured swarm peers.

Peer identity is the certificate pin plus the signed envelope. This module
does not open a shell, does not download dependencies, and does not broadcast
a transaction.
"""
import hashlib
import hmac

import aiohttp
from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

from .codec import decode, encode
from .errors import MeshError, require

MAX_BODY = 1024 * 1024


def cert_pin(pem: str) -> str:
    require(isinstance(pem, str) and 0 < len(pem) < 65536, "CERTIFICATE")
    try:
        der = load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
    except ValueError as exc:
        raise MeshError("CERTIFICATE") from exc
    return hashlib.sha384(der).hexdigest()


async def bounded_body(request, limit: int = MAX_BODY) -> bytes:
    require(isinstance(limit, int) and 0 < limit <= 64 * 1024 * 1024, "BODY_LIMIT")
    if request.content_length is not None:
        require(request.content_length <= limit, "BODY_LIMIT")
    raw = await request.content.read(limit + 1)
    require(len(raw) <= limit, "BODY_LIMIT")
    return raw


@web.middleware
async def errors(request, handler):
    try:
        return await handler(request)
    except MeshError as exc:
        body = encode({"error": exc.code})
        return web.Response(status=400, body=body, content_type="application/json")


class PeerTransport:
    def __init__(self, identity, peers: dict):
        self.identity = identity
        self.peers = dict(peers)
        self.pins = {peer_id: cert_pin(row["certificate"]) for peer_id, row in self.peers.items()}
        self.server_ssl = identity.tls([row["certificate"] for row in self.peers.values()], True)
        self.client_ssl = {peer_id: identity.tls([row["certificate"]], False) for peer_id, row in self.peers.items()}
        self.session = None

    async def start(self):
        if self.session is None:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))

    async def close(self):
        if self.session is not None:
            await self.session.close()
            self.session = None

    def auth(self, request) -> str:
        ssl_object = request.transport.get_extra_info("ssl_object") if request.transport else None
        require(ssl_object is not None, "TLS_REQUIRED")
        der = ssl_object.getpeercert(binary_form=True)
        require(isinstance(der, (bytes, bytearray)) and der, "TLS_PEER")
        pin = hashlib.sha384(der).hexdigest()
        for peer_id, expected in self.pins.items():
            if hmac.compare_digest(pin, expected):
                return peer_id
        raise MeshError("TLS_PIN")

    async def _post(self, peer: str, path: str, body: bytes):
        require(self.session is not None, "TRANSPORT_STOPPED")
        require(peer in self.peers, "UNKNOWN_PEER")
        url = self.peers[peer]["endpoint"].rstrip("/") + path
        async with self.session.post(url, data=body, ssl=self.client_ssl[peer], headers={"Content-Type": "application/json"}) as response:
            raw = await response.read()
            require(response.status == 200, "RPC_STATUS", str(response.status))
            require(len(raw) <= 64 * 1024 * 1024, "BODY_LIMIT")
            return decode(raw, max(len(raw), 1))

    async def rpc(self, peer: str, method: str, payload: dict):
        require(method in {"vote", "append", "snapshot"}, "RAFT_METHOD")
        limit = 64 * 1024 * 1024 if method == "snapshot" else MAX_BODY
        return await self._post(peer, f"/raft/{method}", encode(payload, limit))

    async def command(self, leader: str, envelope: dict):
        return await self._post(leader, "/command", encode(envelope))
