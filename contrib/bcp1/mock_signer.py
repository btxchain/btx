#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""BCP/1 mock external signer (command + loopback HTTPS).

Speaks the existing `-signer` argv protocol (enumerate / getdescriptors /
getp2mrpubkeys / displayaddress / signtx) plus SignerProvider methods:
health, getpubkey, derivepubkey, signdigest.

Signature backend
-----------------
`signdigest` returns a REAL ML-DSA-44 signature produced by the host OpenSSL
3.5+ CLI (`openssl genpkey -algorithm ML-DSA-44`, `openssl pkeyutl -sign
-rawin`). This is a software signer, not an HSM, and it never holds BTX chain
funds. Keys live in a local keystore (`--keystore` / `BTX_BCP1_KEYSTORE`,
default `<cwd>/.bcp1-mock-signer`) addressed by the canonical seed-hardened
path `m/87h/coin_typeh/accounth/branch/index` (branch 0 = deposit, 1 = change).
The signed message is the raw 32-byte canonical P2MR digest: `uint256::GetHex()`
prints the internal bytes reversed, so the digest hex is reversed back before
signing.

`--stub-signature` selects deterministic bytes of the right length instead.
The stub is NOT a signature: it exists only so a test can prove that
`finalizeexternalsign` rejects corrupt input fail-closed. Never treat it as a
signature and never report it as a pass.

SLH-DSA-128s pubkeys are exported so two-leaf fallback descriptors commit to a
real key, but SLH-DSA *signing* fails closed: BTX verifies SLH-DSA messages
with the legacy bare-hash (`slhdsa_fips205=false`) preconditioning, which does
not match OpenSSL's FIPS-205 output. Do not use this mock as an SLH-DSA signer.

ML-DSA-44 cannot do Bitcoin-style non-hardened public child derivation, so
`derivepubkey` is UNSUPPORTED. Canonical seed-side path:
m/87h / coin_typeh / accounth / branch / index (branch 0 = deposit, 1 = change).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

FINGERPRINT = "00000001"
MLDSA44_PUBKEY_SIZE = 1312
MLDSA44_SIGNATURE_SIZE = 2420
SLHDSA128S_PUBKEY_SIZE = 32
SLHDSA128S_SIGNATURE_SIZE = 7856
PROFILE = "BTX_EXCHANGE_PROFILE_V1"
UNSUPPORTED_PUBLIC_CHILD = (
    "ML-DSA-44 cannot do Bitcoin-style non-hardened public child derivation; "
    "derive from the master seed on the signer and export pubkeys "
    "(getp2mrpubkeys / importdepositpool)"
)

# BTX wire algorithm id -> OpenSSL algorithm name.
OPENSSL_ALGORITHM = {
    "ml_dsa_44": "ML-DSA-44",
    "slh_dsa_128s": "SLH-DSA-SHAKE-128s",
}
PUBKEY_SIZE = {
    "ml_dsa_44": MLDSA44_PUBKEY_SIZE,
    "slh_dsa_128s": SLHDSA128S_PUBKEY_SIZE,
}
SIGNATURE_SIZE = {
    "ml_dsa_44": MLDSA44_SIGNATURE_SIZE,
    "slh_dsa_128s": SLHDSA128S_SIGNATURE_SIZE,
}
PRETTY_ALGORITHM = {
    "ml_dsa_44": "ML-DSA-44",
    "slh_dsa_128s": "SLH-DSA-128s",
}
# Only ML-DSA-44 has a signing path that BTX verification accepts (see module doc).
SIGNABLE_ALGORITHMS = ("ml_dsa_44",)

# Process-wide keystore override for --http / --webhook modes.
_KEYSTORE_OVERRIDE: str | None = None


class SignerError(RuntimeError):
    """Fail-closed signer backend error. Never carries secret material."""


def _expand(label: str, size: int) -> bytes:
    """Non-cryptographic deterministic bytes. Only used by --stub-signature."""
    out = bytearray()
    i = 0
    seed = label.encode("utf-8")
    while len(out) < size:
        out.extend(hashlib.sha256(seed + i.to_bytes(4, "big")).digest())
        i += 1
    return bytes(out[:size])


def _emit(obj) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")))


def _path_for(branch: int, index: int, coin_type: int = 1, account: int = 0) -> str:
    return f"m/87h/{coin_type}h/{account}h/{branch}/{index}"


def _wire_algo(args, default: str = "ml_dsa_44") -> str | None:
    """Canonical BTX wire algorithm id, or None for an unknown name (fail closed)."""
    raw = getattr(args, "algo", None) or getattr(args, "algorithm", None) or default
    algo = str(raw).replace("-", "_").lower()
    if algo in ("ml_dsa_44", "mldsa44"):
        return "ml_dsa_44"
    if algo in ("slh_dsa_128s", "slhdsa128s", "slh_dsa_shake_128s"):
        return "slh_dsa_128s"
    return None


def perform_pre_checks() -> None:
    """Test fixture hook: `./mock_result` (first char = exit code)."""
    mock_result_path = os.path.join(os.getcwd(), "mock_result")
    if os.path.isfile(mock_result_path):
        with open(mock_result_path, "r", encoding="utf8") as f:
            mock_result = f.read()
        if mock_result and mock_result[0]:
            sys.stdout.write(mock_result[2:])
            sys.exit(int(mock_result[0]))


# --- software signer backend (OpenSSL CLI) ---------------------------------


def _openssl_bin() -> str:
    return os.environ.get("BTX_BCP1_OPENSSL") or os.environ.get("OPENSSL") or "openssl"


def _openssl_supports(openssl_algo: str) -> tuple[bool, str]:
    """(available, detail). Cached per process."""
    cache = getattr(_openssl_supports, "_cache", None)
    if cache is None:
        cache = {}
        _openssl_supports._cache = cache
    if openssl_algo in cache:
        return cache[openssl_algo]
    available = False
    detail = ""
    try:
        proc = subprocess.run(
            [_openssl_bin(), "list", "-signature-algorithms"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        blob = (proc.stdout or "") + (proc.stderr or "")
        available = proc.returncode == 0 and openssl_algo in blob
        if not available:
            detail = f"{_openssl_bin()} does not advertise {openssl_algo} (needs OpenSSL 3.5+)"
    except (OSError, subprocess.SubprocessError) as exc:
        detail = f"{_openssl_bin()} unavailable: {exc}"
    cache[openssl_algo] = (available, detail)
    return available, detail


def _der_tlv(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    """Minimal DER TLV reader (short and long form lengths)."""
    if pos + 2 > len(buf):
        raise SignerError("truncated DER")
    tag = buf[pos]
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or pos + count > len(buf):
            raise SignerError("indefinite or truncated DER length")
        length = int.from_bytes(buf[pos:pos + count], "big")
        pos += count
    if pos + length > len(buf):
        raise SignerError("DER length out of range")
    return tag, buf[pos:pos + length], pos + length


def _spki_raw_pubkey(der: bytes) -> bytes:
    """Raw PQ public key bytes from an X.509 SubjectPublicKeyInfo DER blob."""
    tag, outer, _ = _der_tlv(der, 0)
    if tag != 0x30:
        raise SignerError("signer public key is not an SPKI SEQUENCE")
    pos = 0
    alg_tag, _, pos = _der_tlv(outer, pos)
    if alg_tag != 0x30:
        raise SignerError("signer public key is missing an AlgorithmIdentifier")
    bits_tag, bits, _ = _der_tlv(outer, pos)
    if bits_tag != 0x03 or not bits or bits[0] != 0x00:
        raise SignerError("signer public key is missing a BIT STRING")
    return bytes(bits[1:])


def _resolve_keystore(args=None) -> str:
    explicit = getattr(args, "keystore", None) if args is not None else None
    if explicit:
        return os.path.abspath(explicit)
    if _KEYSTORE_OVERRIDE:
        return _KEYSTORE_OVERRIDE
    env = os.environ.get("BTX_BCP1_KEYSTORE")
    if env:
        return os.path.abspath(env)
    return os.path.join(os.getcwd(), ".bcp1-mock-signer")


def _key_pem_path(keystore: str, wire_algo: str, path: str) -> str:
    name = hashlib.sha256(f"bcp1|{wire_algo}|{path}".encode("utf-8")).hexdigest()[:32]
    return os.path.join(keystore, wire_algo, name + ".pem")


def _run_openssl(argv: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, timeout=300, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SignerError(f"openssl invocation failed: {exc}") from exc


def _ensure_key(pem_path: str, openssl_algo: str) -> None:
    if os.path.isfile(pem_path):
        return
    os.makedirs(os.path.dirname(pem_path), exist_ok=True)
    tmp = f"{pem_path}.tmp{os.getpid()}"
    proc = _run_openssl([_openssl_bin(), "genpkey", "-algorithm", openssl_algo, "-out", tmp])
    if proc.returncode != 0 or not os.path.isfile(tmp):
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise SignerError(f"openssl genpkey {openssl_algo} failed: {_openssl_error(proc)}")
    # Atomic publish. Callers always re-read the published file, so a racer
    # converges on the winner's key instead of signing with a different one.
    os.replace(tmp, pem_path)


def _openssl_error(proc: subprocess.CompletedProcess) -> str:
    blob = (proc.stderr or b"").decode("utf-8", "replace")
    blob = " ".join(blob.split())
    return blob[-300:] if blob else "no stderr"


def export_pubkey(keystore: str, wire_algo: str, path: str) -> bytes:
    openssl_algo = OPENSSL_ALGORITHM[wire_algo]
    available, detail = _openssl_supports(openssl_algo)
    if not available:
        raise SignerError(f"SIGNER_BACKEND_UNAVAILABLE: {detail}")
    pem_path = _key_pem_path(keystore, wire_algo, path)
    _ensure_key(pem_path, openssl_algo)
    proc = _run_openssl([_openssl_bin(), "pkey", "-in", pem_path, "-pubout", "-outform", "DER"])
    if proc.returncode != 0:
        raise SignerError(f"openssl pkey -pubout failed: {_openssl_error(proc)}")
    raw = _spki_raw_pubkey(proc.stdout)
    expected = PUBKEY_SIZE[wire_algo]
    if len(raw) != expected:
        raise SignerError(f"signer pubkey size {len(raw)} != {expected}")
    return raw


def digest_message_bytes(digest_hex: str) -> bytes:
    """Canonical 32-byte digest as the node signs it.

    `uint256::GetHex()` prints the internal byte array reversed (bitcoin-style
    display order) while `CPQKey::Sign` / `CPQPubKey::Verify` consume
    `uint256::data()` in internal order. Reverse back before signing.
    """
    try:
        raw = bytes.fromhex(digest_hex)
    except ValueError as exc:
        raise SignerError("digest must be hex") from exc
    if len(raw) != 32:
        raise SignerError(f"digest must be 32 bytes, got {len(raw)}")
    return raw[::-1]


def sign_digest(keystore: str, wire_algo: str, path: str, digest_hex: str) -> bytes:
    if wire_algo not in SIGNABLE_ALGORITHMS:
        raise SignerError(
            "SLH_DSA_SIGN_UNAVAILABLE: BTX verifies SLH-DSA with legacy bare-hash "
            "preconditioning; OpenSSL emits FIPS-205 output. Refusing to emit a "
            "signature that finalizeexternalsign would reject."
        )
    message = digest_message_bytes(digest_hex)
    openssl_algo = OPENSSL_ALGORITHM[wire_algo]
    available, detail = _openssl_supports(openssl_algo)
    if not available:
        raise SignerError(f"SIGNER_BACKEND_UNAVAILABLE: {detail}")
    pem_path = _key_pem_path(keystore, wire_algo, path)
    _ensure_key(pem_path, openssl_algo)
    with tempfile.TemporaryDirectory(dir=os.path.dirname(pem_path)) as work:
        msg_path = os.path.join(work, "message.bin")
        sig_path = os.path.join(work, "signature.bin")
        with open(msg_path, "wb") as handle:
            handle.write(message)
        proc = _run_openssl([
            _openssl_bin(), "pkeyutl", "-sign", "-inkey", pem_path,
            "-rawin", "-in", msg_path, "-out", sig_path,
        ])
        if proc.returncode != 0 or not os.path.isfile(sig_path):
            raise SignerError(f"openssl pkeyutl -sign failed: {_openssl_error(proc)}")
        with open(sig_path, "rb") as handle:
            signature = handle.read()
    expected = SIGNATURE_SIZE[wire_algo]
    if len(signature) != expected:
        raise SignerError(f"signer signature size {len(signature)} != {expected}")
    return signature


def _canonical_path_from_descriptor(desc: str, index: int) -> str | None:
    """Map `mr(pqhd(<fingerprint>/<coin>h/<account>h/<branch>/*))` to the
    canonical BCP/1 path. Purpose 87h is implied by pqhd()."""
    match = re.search(r"pqhd\(([^)]*)\)", desc or "")
    if not match:
        return None
    parts = [part for part in match.group(1).split("/") if part != ""]
    if len(parts) < 4:
        return None
    coin, account, branch = parts[1], parts[2], parts[3]
    if not coin.endswith(("h", "H", "'")) or not account.endswith(("h", "H", "'")):
        return None
    if branch not in ("0", "1"):
        return None
    return f"m/87h/{coin}/{account}/{branch}/{index}"


# --- argv commands ---------------------------------------------------------


def enumerate_cmd(_args) -> None:
    _emit([{
        "fingerprint": FINGERPRINT,
        "type": "command",
        "model": "bcp1_mock",
        "name": "bcp1_mock",
        "capabilities": {
            "p2mr": True,
            "pq_algorithms": list(SIGNABLE_ALGORITHMS),
            "pubkey_algorithms": ["ml_dsa_44", "slh_dsa_128s"],
            "signing_algorithms": list(SIGNABLE_ALGORITHMS),
            "public_child_derivation": False,
            "software_signer": True,
            "profile": PROFILE,
        },
    }])


def getdescriptors(args) -> None:
    # `-signer` import path. pqhd(fingerprint/coin_typeh/accounth/change/*)
    # expands to m/87h/<coin>h/<account>h/<branch>/<index>; getpubkey /
    # getp2mrpubkeys supply the concrete ML-DSA / SLH-DSA pubkeys.
    receive_key = f"pqhd({FINGERPRINT}/1h/0h/0/*)"
    internal_key = f"pqhd({FINGERPRINT}/1h/0h/1/*)"
    _emit({
        "receive": [f"mr({receive_key},pk_slh({receive_key}))"],
        "internal": [f"mr({internal_key},pk_slh({internal_key}))"],
    })


def getp2mrpubkeys(args) -> None:
    if args.fingerprint and args.fingerprint != FINGERPRINT:
        _emit({"error": "Unexpected fingerprint", "fingerprint": args.fingerprint})
        return
    if args.desc is None or args.index is None:
        _emit({"error": "Missing descriptor/index"})
        return
    try:
        index = int(str(args.index))
    except ValueError:
        _emit({"error": "index must be an integer"})
        return
    path = _canonical_path_from_descriptor(str(args.desc), index)
    if path is None:
        _emit({"error": "UNSUPPORTED_DESCRIPTOR", "reason": "cannot map pqhd() to m/87h/.../<branch>/<index>"})
        return
    keystore = _resolve_keystore(args)
    try:
        slh = export_pubkey(keystore, "slh_dsa_128s", path)
        ml = export_pubkey(keystore, "ml_dsa_44", path)
    except SignerError as exc:
        _emit({"error": str(exc)})
        return
    _emit({
        "entries": [
            {"expr_index": 0, "algo": "slh_dsa_128s", "pubkey": slh.hex()},
            {"expr_index": 1, "algo": "ml_dsa_44", "pubkey": ml.hex()},
        ],
        "path": path,
        "fingerprint": FINGERPRINT,
    })


def displayaddress(args) -> None:
    # The mock does not render addresses on a device; fail closed rather than
    # echo a placeholder the wallet would reject as a mismatch anyway.
    _emit({
        "error": "DISPLAY_ADDRESS_UNSUPPORTED",
        "reason": "bcp1_mock is a software signer with no display; use getpubkey/deriveaddresses",
        "fingerprint": args.fingerprint or FINGERPRINT,
    })


def signtx(args) -> None:
    # Legacy `-signer signtx` PSBT hook. Only returns a fixture when the test
    # writes ./mock_psbt; otherwise it reports the PSBT as incomplete.
    mock_psbt_path = os.path.join(os.getcwd(), "mock_psbt")
    if os.path.isfile(mock_psbt_path):
        with open(mock_psbt_path, "r", encoding="utf8") as f:
            mock_psbt = f.read().strip()
        _emit({"psbt": mock_psbt, "complete": True, "stub": True,
               "warning": "mock_psbt fixture: not a real signature"})
        return
    _emit({"psbt": args.psbt, "complete": False})


def health(args) -> None:
    chain = args.chain or "regtest"
    available, detail = _openssl_supports(OPENSSL_ALGORITHM["ml_dsa_44"])
    result = {
        "ok": available,
        "fingerprint": FINGERPRINT,
        "profile": PROFILE,
        "network": chain,
        "algorithm": "ML-DSA-44",
        "algorithms": ["ML-DSA-44"],
        "pq_algorithms": list(SIGNABLE_ALGORITHMS),
        "pubkey_algorithms": ["ml_dsa_44", "slh_dsa_128s"],
        "signing_algorithms": list(SIGNABLE_ALGORITHMS),
        "p2mr": True,
        "software_signer": True,
        "hardware": False,
        "public_child_derivation": False,
        "path": "m/87h/coin_typeh/accounth/branch/index",
        "signer_backend": f"openssl:{OPENSSL_ALGORITHM['ml_dsa_44']}",
    }
    if not available:
        result["error"] = "SIGNER_BACKEND_UNAVAILABLE"
        result["detail"] = detail
    _emit(result)


def getpubkey(args) -> None:
    path = args.path or _path_for(0, 0)
    wire = _wire_algo(args)
    if wire is None:
        _emit({"error": "UNKNOWN_ALGORITHM", "algorithm": getattr(args, "algorithm", None) or getattr(args, "algo", None)})
        return
    keystore = _resolve_keystore(args)
    try:
        pubkey = export_pubkey(keystore, wire, path)
    except SignerError as exc:
        _emit({"error": str(exc)})
        return
    _emit({
        "pubkey": pubkey.hex(),
        "path": path,
        "algo": wire,
        "algorithm": PRETTY_ALGORITHM[wire],
        "fingerprint": FINGERPRINT,
        "backend": f"openssl:{OPENSSL_ALGORITHM[wire]}",
        "stub": False,
    })


def derivepubkey(_args) -> None:
    _emit({
        "error": "UNSUPPORTED",
        "code": "UNSUPPORTED",
        "reason": UNSUPPORTED_PUBLIC_CHILD,
    })


def signdigest(args) -> None:
    digest = args.digest or ""
    path = args.path or _path_for(0, 0)
    wire = _wire_algo(args)
    if wire is None:
        _emit({"error": "UNKNOWN_ALGORITHM", "algorithm": getattr(args, "algorithm", None) or getattr(args, "algo", None)})
        return
    if getattr(args, "stub_signature", False):
        signature = _expand(f"stub|{wire}|{path}|{digest}", SIGNATURE_SIZE[wire])
        _emit({
            "signature": signature.hex(),
            "algo": wire,
            "algorithm": PRETTY_ALGORITHM[wire],
            "digest": digest,
            "path": path,
            "fingerprint": FINGERPRINT,
            "stub": True,
            "warning": "non-cryptographic stub; finalizeexternalsign must reject it",
        })
        return
    keystore = _resolve_keystore(args)
    try:
        signature = sign_digest(keystore, wire, path, digest)
    except SignerError as exc:
        _emit({"error": str(exc), "path": path, "digest": digest, "algo": wire})
        return
    _emit({
        "signature": signature.hex(),
        "algo": wire,
        "algorithm": PRETTY_ALGORITHM[wire],
        "digest": digest,
        "path": path,
        "fingerprint": FINGERPRINT,
        "backend": f"openssl:{OPENSSL_ALGORITHM[wire]}",
        "stub": False,
    })


def _provider_dispatch(method: str, params: dict) -> dict:
    method = method.replace("-", "_").lower().strip("/")
    aliases = {
        "health": "health",
        "get_public_key": "getpubkey",
        "getpublickey": "getpubkey",
        "getpubkey": "getpubkey",
        "derive_public_key": "derivepubkey",
        "derivepublickey": "derivepubkey",
        "derivepubkey": "derivepubkey",
        "sign_digest": "signdigest",
        "signdigest": "signdigest",
        "enumerate": "enumerate",
        "getp2mrpubkeys": "getp2mrpubkeys",
        "get_descriptors": "getdescriptors",
        "getdescriptors": "getdescriptors",
        "displayaddress": "displayaddress",
    }
    mapped = aliases.get(method)
    if mapped is None:
        return {"error": f"unknown method {method}"}
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        ns = argparse.Namespace(
            fingerprint=params.get("fingerprint", FINGERPRINT),
            chain=params.get("chain", "regtest"),
            account=params.get("account", "0"),
            desc=params.get("desc"),
            index=params.get("index"),
            path=params.get("path"),
            digest=params.get("digest"),
            algo=params.get("algorithm") or params.get("algo"),
            psbt=params.get("psbt"),
            keystore=params.get("keystore"),
            stub_signature=bool(params.get("stub_signature", False)),
        )
        {
            "health": health,
            "getpubkey": getpubkey,
            "derivepubkey": derivepubkey,
            "signdigest": signdigest,
            "enumerate": enumerate_cmd,
            "getp2mrpubkeys": getp2mrpubkeys,
            "getdescriptors": getdescriptors,
            "displayaddress": displayaddress,
        }[mapped](ns)
    finally:
        sys.stdout = old
    raw = buf.getvalue()
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"raw": raw}


class SignerHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A003
        sys.stderr.write("[mock-signer] " + (fmt % args) + "\n")

    def _send(self, code: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path in ("/", "/health"):
            self._send(200, _provider_dispatch("health", {"chain": "regtest"}))
            return
        if path == "/events":
            events = getattr(self.server, "events", [])
            self._send(200, {"events": events})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        body = self._read_json()
        if path == "/event":
            events = getattr(self.server, "events", None)
            if events is None:
                self.server.events = []
                events = self.server.events
            events.append(body)
            self._send(200, {"ok": True, "stored": len(events)})
            return
        method = body.get("method") if isinstance(body.get("method"), str) else path.strip("/")
        params = body.get("params") if isinstance(body.get("params"), dict) else body
        if not method or method == "event":
            self._send(400, {"error": "missing method"})
            return
        result = _provider_dispatch(method, params)
        code = 200
        if isinstance(result, dict) and str(result.get("error", "")).startswith("unknown"):
            code = 404
        self._send(code, result)


def serve(bind: str, webhook: bool) -> None:
    if ":" in bind:
        host, port_s = bind.rsplit(":", 1)
        port = int(port_s)
    else:
        host, port = "127.0.0.1", int(bind)
    httpd = ThreadingHTTPServer((host, port), SignerHandler)
    httpd.events = []
    kind = "webhook" if webhook else "signer"
    sys.stderr.write(f"BCP/1 mock {kind} listening on {host}:{port}\n")
    httpd.serve_forever()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mock_signer.py",
        description=(
            "BCP/1 mock external signer: argv -signer protocol, SignerProvider JSON "
            "(health, getpubkey, getp2mrpubkeys, derivepubkey, signdigest), loopback "
            "--http, and --webhook event sink. signdigest emits real ML-DSA-44 "
            "signatures via the host OpenSSL CLI; --stub-signature is a "
            "non-cryptographic negative-test fixture."
        ),
    )
    parser.add_argument("--fingerprint", help="Expected device fingerprint (default 00000001)")
    parser.add_argument("--chain", default="regtest", help="Chain name for health responses")
    parser.add_argument("--keystore", metavar="DIR",
                        help="Software signer key store (default $BTX_BCP1_KEYSTORE or ./.bcp1-mock-signer)")
    parser.add_argument("--stdin", action="store_true", help="Read JSON command from stdin when argv is empty")
    parser.add_argument("--http", metavar="HOST:PORT", help="Serve SignerProvider over loopback HTTP")
    parser.add_argument("--webhook", metavar="HOST:PORT", help="Serve a JSON event sink (POST /event)")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("enumerate", help="List mock signer devices")
    p.set_defaults(func=enumerate_cmd)

    p = sub.add_parser("getdescriptors", help="Return pqhd descriptors for -signer import")
    p.add_argument("--account", metavar="account")
    p.set_defaults(func=getdescriptors)

    p = sub.add_parser("getp2mrpubkeys", help="Return real P2MR pubkeys for a descriptor index")
    p.add_argument("--desc", metavar="desc")
    p.add_argument("--index", metavar="index")
    p.set_defaults(func=getp2mrpubkeys)

    p = sub.add_parser("displayaddress", help="On-device address display (UNSUPPORTED, fail-closed)")
    p.add_argument("--desc", metavar="desc")
    p.set_defaults(func=displayaddress)

    p = sub.add_parser("signtx", help="Fixture PSBT hook for legacy -signer signtx")
    p.add_argument("psbt", nargs="?", default="")
    p.set_defaults(func=signtx)

    p = sub.add_parser("signtransaction", help="Alias for signtx")
    p.add_argument("psbt", nargs="?", default="")
    p.set_defaults(func=signtx)

    p = sub.add_parser("health", help="SignerProvider health probe")
    p.set_defaults(func=health)

    p = sub.add_parser("getpubkey", help="Export a real PQ pubkey for a BIP-87 path")
    p.add_argument("--path")
    p.add_argument("--algo")
    p.add_argument("--algorithm")
    p.set_defaults(func=getpubkey)

    p = sub.add_parser("get_public_key", help="Alias for getpubkey")
    p.add_argument("--path")
    p.add_argument("--algo")
    p.add_argument("--algorithm")
    p.set_defaults(func=getpubkey)

    p = sub.add_parser("derivepubkey", help="Public child derivation (always UNSUPPORTED for ML-DSA-44)")
    p.add_argument("--path")
    p.set_defaults(func=derivepubkey)

    p = sub.add_parser("derive_public_key", help="Alias for derivepubkey")
    p.add_argument("--path")
    p.set_defaults(func=derivepubkey)

    p = sub.add_parser("signdigest", help="Real ML-DSA-44 signature over a 32-byte canonical digest")
    p.add_argument("--path")
    p.add_argument("--digest")
    p.add_argument("--algo")
    p.add_argument("--algorithm")
    p.add_argument("--stub-signature", action="store_true",
                   help="Emit a non-cryptographic stub (negative test only). Not a signature.")
    p.set_defaults(func=signdigest)

    p = sub.add_parser("sign_digest", help="Alias for signdigest")
    p.add_argument("--path")
    p.add_argument("--digest")
    p.add_argument("--algo")
    p.add_argument("--algorithm")
    p.add_argument("--stub-signature", action="store_true",
                   help="Emit a non-cryptographic stub (negative test only). Not a signature.")
    p.set_defaults(func=signdigest)

    return parser


def main(argv=None) -> int:
    global _KEYSTORE_OVERRIDE
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    # ExternalSigner passes "<command> {json}" (or a bare JSON envelope) on
    # stdin, while legacy callers append leftover argv tokens. Only touch stdin
    # when the caller asked for it: btxd may start the signer with an open pipe
    # on fd 0 and an unconditional read would block the RPC.
    envelope = None
    want_stdin = "--stdin" in argv or not argv
    if want_stdin and not sys.stdin.isatty():
        buffer = sys.stdin.read()
        stripped = buffer.strip()
        if stripped:
            payload = None
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError:
                    payload = None
            else:
                first, sep, rest = stripped.partition(" ")
                if sep and rest.lstrip().startswith(("{", "[")):
                    try:
                        payload = json.loads(rest)
                    except json.JSONDecodeError:
                        payload = None
                    if isinstance(payload, dict):
                        payload.setdefault("method", first)
                if payload is None:
                    argv.extend(stripped.split(" "))
            if isinstance(payload, dict):
                envelope = payload

    args = parser.parse_args(argv)
    if args.keystore:
        _KEYSTORE_OVERRIDE = os.path.abspath(args.keystore)

    if envelope is not None:
        method = str(envelope.get("command") or envelope.get("method") or "signdigest")
        params = envelope.get("params") if isinstance(envelope.get("params"), dict) else envelope
        _emit(_provider_dispatch(method, params))
        return 0

    if args.http:
        serve(args.http, webhook=False)
        return 0
    if args.webhook:
        serve(args.webhook, webhook=True)
        return 0
    if not args.command:
        parser.print_help()
        return 2
    perform_pre_checks()
    if args.command in ("signdigest", "sign_digest", "getpubkey", "get_public_key") and getattr(args, "algorithm", None) and not getattr(args, "algo", None):
        args.algo = args.algorithm
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
