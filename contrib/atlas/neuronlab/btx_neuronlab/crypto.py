"""ML-DSA-44 signing via OpenSSL 3.5+. No wallet keys, no fallback suite.

Publisher identities are explicitly NeuronLab research identities. A matching
algorithm does not make them a BTX PIT root; native identity binding is separate.
"""
from __future__ import annotations
import base64
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from .codec import LabError, require, keys, digest_text, canonical, sha384, read_file, atomic_write

OID_MLDSA44 = bytes.fromhex('0609608648016503040311')
SIG_BYTES = 2420
DOMAINS = {'profile': b'BTX/NeuronLab/SignedProfile/1\0',
           'evidence': b'BTX/NeuronLab/SignedEvidence/1\0'}

class MLDSA44:
    def __init__(self, executable: str | None = None):
        self.exe = executable or shutil.which('openssl')
        require(bool(self.exe) and Path(self.exe).is_file(), 'CRYPTO_UNAVAILABLE', 'OpenSSL with ML-DSA-44 is required')
        self.exe = str(Path(self.exe).resolve())

    def run(self, args, *, data=None):
        env = {k: v for k, v in os.environ.items() if k in ('SYSTEMROOT', 'WINDIR', 'HOME', 'TMPDIR', 'TEMP', 'TMP')}
        # Block externally injected OpenSSL config/modules from changing providers.
        env['OPENSSL_CONF'] = os.devnull
        try:
            p = subprocess.run([self.exe, *args], input=data, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=15, env=env, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise LabError('CRYPTO_UNAVAILABLE', 'OpenSSL operation unavailable or timed out') from e
        require(len(p.stdout) <= 65536 and len(p.stderr) <= 65536, 'CRYPTO_OUTPUT', 'Oversized crypto output')
        require(p.returncode == 0, 'CRYPTO_REJECTED', 'ML-DSA-44 operation failed; no fallback is permitted')
        return p.stdout

    def generate(self, key_file: Path):
        require(not key_file.exists(), 'EXISTS', 'Research key already exists')
        # The key is created in a private temporary directory then atomically
        # installed with owner-only permissions, never returned to the renderer.
        with tempfile.TemporaryDirectory(prefix='btx-ml-dsa-') as d:
            p = Path(d) / 'private.pem'
            self.run(['genpkey', '-algorithm', 'ML-DSA-44', '-out', str(p)])
            atomic_write(key_file, read_file(p, 16384), replace=False)
        return self.public_key(key_file)

    def public_key(self, key_file: Path) -> bytes:
        require(not key_file.is_symlink(), 'KEY', 'Symlink key refused')
        if os.name == 'posix':
            require(key_file.stat().st_mode & 0o077 == 0, 'KEY_MODE', 'Research private key must be owner-only')
        pub = self.run(['pkey', '-in', str(key_file), '-pubout', '-outform', 'DER'])
        self.validate_public(pub)
        return pub

    @staticmethod
    def validate_public(pub: bytes):
        # Standard SubjectPublicKeyInfo for ML-DSA-44: OID and 1312-byte public key.
        require(1300 < len(pub) < 1400 and OID_MLDSA44 in pub[:32], 'KEY_SUITE', 'Not an ML-DSA-44 SPKI')

    def sign(self, record: dict, key_file: Path, *, kind='profile') -> dict:
        pub = self.public_key(key_file)
        require(kind in DOMAINS, 'SIGN_DOMAIN', 'Unknown signed object domain')
        message = DOMAINS[kind] + canonical(record)
        with tempfile.TemporaryDirectory(prefix='btx-sign-') as d:
            p = Path(d) / 'message'
            p.write_bytes(message)
            sig = self.run(['pkeyutl', '-sign', '-rawin', '-inkey', str(key_file), '-in', str(p)])
        require(len(sig) == SIG_BYTES, 'SIGNATURE', 'Wrong ML-DSA-44 signature length')
        return {'suite': 'ML-DSA-44', 'public_key_der': base64.b64encode(pub).decode(),
                'publisher': sha384(b'BTX/NeuronLab/Publisher/1\0' + pub),
                'signature': base64.b64encode(sig).decode()}

    def verify(self, record: dict, signed: dict, *, kind='profile') -> str:
        keys(signed, {'suite', 'public_key_der', 'publisher', 'signature'})
        require(signed['suite'] == 'ML-DSA-44', 'KEY_SUITE', 'Unknown signature suite')
        digest_text(signed['publisher'])
        try:
            pub = base64.b64decode(signed['public_key_der'], validate=True)
            sig = base64.b64decode(signed['signature'], validate=True)
        except (ValueError, TypeError) as e:
            raise LabError('SIGNATURE', 'Invalid signature encoding') from e
        self.validate_public(pub)
        require(len(sig) == SIG_BYTES, 'SIGNATURE', 'Wrong signature length')
        require(sha384(b'BTX/NeuronLab/Publisher/1\0' + pub) == signed['publisher'], 'KEY_ID', 'Publisher identity mismatch')
        with tempfile.TemporaryDirectory(prefix='btx-verify-') as d:
            root = Path(d)
            (root/'key.der').write_bytes(pub)
            (root/'signature').write_bytes(sig)
            require(kind in DOMAINS, 'SIGN_DOMAIN', 'Unknown signed object domain')
            (root/'message').write_bytes(DOMAINS[kind] + canonical(record))
            self.run(['pkeyutl', '-verify', '-rawin', '-pubin', '-keyform', 'DER', '-inkey', str(root/'key.der'),
                      '-sigfile', str(root/'signature'), '-in', str(root/'message')])
        return signed['publisher']
