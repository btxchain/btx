#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Owner-enrolled public peer setup for the real three-host WAN scenario.

No public domains or transport identities are invented. Numeric global IPs and
independently pinned PQ1 identities must be supplied by the deployment owner.
The supplied local certificate/key are copied into only the fresh private node.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import time

try:
    from .evidence import EvidenceError, atomic_json, sha256_file, strict_json
except ImportError:
    from evidence import EvidenceError, atomic_json, sha256_file, strict_json


def public_endpoint(value: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError("WAN endpoint must be a numeric public IP and port")
    if value.startswith("[") and "]:" in value:
        host, port = value[1:].split("]:", 1)
    elif value.count(":") == 1:
        host, port = value.rsplit(":", 1)
    else:
        raise EvidenceError("WAN endpoint must be public-IP:port or [public-IPv6]:port")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise EvidenceError("WAN endpoints must be explicitly enrolled numeric addresses") from exc
    if not address.is_global or address.is_multicast or address.is_unspecified or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise EvidenceError("private, loopback, multicast, reserved, and invalid WAN endpoints are refused")
    return ("[" + str(address) + "]" if address.version == 6 else str(address)) + ":" + str(int(port))


def validate_enrollment(path: Path, expected_sha256: str) -> dict:
    if sha256_file(path) != expected_sha256:
        raise EvidenceError("WAN enrollment manifest differs from independent owner pin")
    data = strict_json(Path(path).read_bytes())
    if data.get("schema") != "BTX-WAN-ENROLLMENT/1" or data.get("network") != "regtest":
        raise EvidenceError("WAN acceptance requires explicit regtest enrollment")
    peers, endpoints, identities = data.get("peers"), set(), set()
    if not isinstance(peers, list) or not 2 <= len(peers) <= 16:
        raise EvidenceError("three-host WAN requires two to sixteen enrolled remote peers")
    for row in peers:
        endpoint = public_endpoint(row.get("endpoint"))
        pin = row.get("transport_pin", "")
        if endpoint != row["endpoint"] or endpoint in endpoints or pin in identities or not re.fullmatch(r"[0-9a-f]{96}", pin):
            raise EvidenceError("WAN requires canonical endpoints and distinct independently pinned PQ1 identities")
        endpoints.add(endpoint)
        identities.add(pin)
    local = data.get("local", {})
    if type(local.get("model_port")) is not int or not 1024 <= local["model_port"] <= 65535:
        raise EvidenceError("WAN scenario requires an explicit unprivileged model listen port")
    for name in ("certificate", "private_key"):
        entry = local.get(name, {})
        source = Path(entry.get("path", ""))
        if not source.is_absolute() or sha256_file(source, 1024 * 1024) != entry.get("sha256"):
            raise EvidenceError("enrolled local TLS material differs from pin")
        if name == "private_key" and os.name == "posix":
            status = source.stat()
            if status.st_mode & 0o077 or status.st_uid != os.getuid():
                raise EvidenceError("WAN enrollment private key must be owner-only and owned by this user")
    return data


def configure(path: Path, expected_sha256: str, datadir: Path) -> dict:
    data = validate_enrollment(path, expected_sha256)
    tls = datadir / "regtest" / "modelnet" / "tls"
    tls.mkdir(parents=True, mode=0o700)
    for source_name, filename in (("certificate", "cert.pem"), ("private_key", "key.pem")):
        source = Path(data["local"][source_name]["path"])
        destination = tls / filename
        with destination.open("xb") as output:
            output.write(source.read_bytes())
        destination.chmod(0o600)
        if sha256_file(destination) != data["local"][source_name]["sha256"]:
            raise EvidenceError("WAN TLS material changed while copying into private scenario")
    atomic_json(tls / "pins.json", {row["endpoint"]: row["transport_pin"] for row in data["peers"]})
    return data


def observed_peers(native: dict, enrollment: dict) -> list[dict]:
    if native.get("network") != enrollment["network"]:
        raise EvidenceError("WAN observation is from another chain namespace")
    now = time.time_ns() // 1_000_000
    observed = {row.get("endpoint"): row for row in native.get("peer_observations", [])}
    matched = []
    for expected in enrollment["peers"]:
        row = observed.get(expected["endpoint"], {})
        if row.get("transport_pin") != expected["transport_pin"] or row.get("compute_authorized") is not False:
            raise EvidenceError("enrolled public peer has no matching strict PQ1 observation")
        if type(row.get("expires_at_ms")) is not int or type(row.get("observed_at_ms")) is not int:
            raise EvidenceError("WAN observation lacks measured timestamps")
        if not 0 <= now - row["observed_at_ms"] < 90000 or row["expires_at_ms"] <= now:
            raise EvidenceError("WAN peer observation expired or is from the future")
        matched.append(row)
    return matched
