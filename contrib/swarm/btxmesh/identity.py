"""ML-DSA-44 through OpenSSL 3.5+, without an elliptic-curve fallback.
Private keys stay on this host. Signatures are only on control records, not tokens.
The local OpenSSL executable is operator software, not a remotely supplied command.
"""
import base64
import hashlib
import os
import shutil
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from .codec import encode, decode, byte_id, fields
from .errors import MeshError, require
from .storage import atomic_write, private_dir


def run(args: list[str]):
    exe = shutil.which("openssl")
    require(bool(exe), "OPENSSL_REQUIRED", "OpenSSL >=3.5 with ML-DSA-44")
    result = subprocess.run([exe, *args], capture_output=True, timeout=20, check=False)
    require(result.returncode == 0, "CRYPTO", result.stderr.decode(errors="replace")[:300])
    return result.stdout


class Identity:
    def __init__(self, directory: Path):
        self.directory = private_dir(Path(directory))
        self.key = self.directory / "identity.pem"
        self.pub = self.directory / "public.pem"
        self.cert = self.directory / "certificate.pem"
        if not self.key.exists():
            with tempfile.TemporaryDirectory(dir=self.directory) as td:
                k, p, c = [str(Path(td) / x) for x in ("k", "p", "c")]
                run(["genpkey", "-algorithm", "ML-DSA-44", "-out", k])
                run(["pkey", "-in", k, "-pubout", "-out", p])
                run(["req", "-new", "-x509", "-key", k, "-out", c, "-days", "365",
                     "-subj", "/CN=BTX-Swarm", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"])
                atomic_write(self.key, Path(k).read_bytes())
                atomic_write(self.pub, Path(p).read_bytes())
                atomic_write(self.cert, Path(c).read_bytes())
        require(self.pub.exists() and self.cert.exists(), "IDENTITY_INCOMPLETE")
        require(not self.key.is_symlink(), "SYMLINK")
        os.chmod(self.key, 0o600)
        text = run(["pkey", "-in", str(self.key), "-text", "-noout"])
        require(b"ML-DSA-44" in text, "WRONG_CRYPTO_SUITE")
        self.public = self.pub.read_text()
        self.id = byte_id(run(["pkey", "-pubin", "-in", str(self.pub), "-outform", "DER"]))
    def sign_bytes(self, body: bytes) -> str:
        with tempfile.TemporaryDirectory(dir=self.directory) as td:
            m, s = Path(td)/"message", Path(td)/"sig"
            atomic_write(m, body)
            run(["pkeyutl", "-sign", "-rawin", "-inkey", str(self.key), "-in", str(m), "-out", str(s)])
            return base64.b64encode(s.read_bytes()).decode()
    def envelope(self, payload: dict, *, now_ms: int | None = None, ttl_ms: int = 30000):
        now_ms = now_ms if now_ms is not None else int(time.time()*1000)
        body = {"protocol": "BTX-SWARM/1", "suite": "ML-DSA-44", "sender": self.id,
                "created_ms": now_ms, "expires_ms": now_ms+ttl_ms, "nonce": os.urandom(24).hex(), "payload": payload}
        return {"body": body, "signature": self.sign_bytes(b"BTX-SWARM/1\x00"+encode(body))}
    def tls(self, trust_certs: list[str], server: bool):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if not server: ctx.check_hostname = False  # exact pinned self-signed roots, plus envelope identity
        ctx.load_cert_chain(str(self.cert), str(self.key))
        ctx.load_verify_locations(cadata="\n".join(trust_certs))
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx


def verify(public: str, body: bytes, signature: str) -> str:
    require(isinstance(public,str) and len(public)<16384, "PUBLIC_KEY")
    require(isinstance(signature,str) and len(signature)<16384, "SIGNATURE")
    with tempfile.TemporaryDirectory() as td:
        p,m,s=[Path(td)/x for x in ("pub","message","sig")]
        try: raw=base64.b64decode(signature, validate=True)
        except ValueError as e: raise MeshError("SIGNATURE") from e
        require(len(raw)==2420, "SIGNATURE_LENGTH")
        atomic_write(p,public.encode());atomic_write(m,body);atomic_write(s,raw)
        require(b"ML-DSA-44" in run(["pkey","-pubin","-in",str(p),"-text","-noout"]), "WRONG_CRYPTO_SUITE")
        run(["pkeyutl","-verify","-rawin","-pubin","-inkey",str(p),"-in",str(m),"-sigfile",str(s)])
        return byte_id(run(["pkey","-pubin","-in",str(p),"-outform","DER"]))


def verify_envelope(env: dict, keys: dict[str,str], now_ms=None):
    fields(env,{"body","signature"})
    b=env["body"]
    fields(b,{"protocol","suite","sender","created_ms","expires_ms","nonce","payload"})
    require(b["protocol"]=="BTX-SWARM/1" and b["suite"]=="ML-DSA-44", "PROTOCOL")
    now_ms=now_ms if now_ms is not None else int(time.time()*1000)
    require(type(b["created_ms"]) is int and type(b["expires_ms"]) is int, "TIME")
    require(b["created_ms"]-5000<=now_ms<=b["expires_ms"] and 0<b["expires_ms"]-b["created_ms"]<=60000,"EXPIRED")
    require(isinstance(b["nonce"],str) and len(b["nonce"])==48,"NONCE")
    require(b["sender"] in keys, "UNKNOWN_IDENTITY")
    sender=verify(keys[b["sender"]], b"BTX-SWARM/1\x00"+encode(b), env["signature"])
    require(sender==b["sender"],"IDENTITY_MISMATCH")
    return b
