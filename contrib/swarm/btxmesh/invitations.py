"""Recipient-bound ML-KEM-768/AES-GCM invitations signed with ML-DSA-44.

These establish explicitly approved trust and secret sharing, not a Sybil-proof
identity system. They do not turn a worker invitation into voter authority.
"""
import base64
import os
import tempfile
import time
from pathlib import Path
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .identity import run,verify
from .codec import encode,decode,byte_id,fields
from .storage import atomic_write
from .errors import require,MeshError


def kem_keys(identity):
    key,pub=identity.directory/"kem.pem",identity.directory/"kem-public.pem"
    if not key.exists():
        with tempfile.TemporaryDirectory(dir=identity.directory) as td:
            k,p=Path(td)/"k",Path(td)/"p"
            run(["genpkey","-algorithm","ML-KEM-768","-out",str(k)])
            run(["pkey","-in",str(k),"-pubout","-out",str(p)])
            atomic_write(key,k.read_bytes());atomic_write(pub,p.read_bytes())
    require(pub.exists(),"KEM_KEY_INCOMPLETE")
    require(b"ML-KEM-768" in run(["pkey","-pubin","-in",str(pub),"-text","-noout"]),"KEM_SUITE")
    return key,pub


def bundle(identity,endpoint):
    _,pub=kem_keys(identity)
    body={"identity":identity.id,"public_key":identity.public,"kem_public_key":pub.read_text(),"certificate":identity.cert.read_text(),"endpoint":endpoint}
    return {"body":body,"signature":identity.sign_bytes(b"BTX/PeerBundle/1\x00"+encode(body))}


def check_bundle(bundle):
    fields(bundle,{"body","signature"});b=bundle["body"]
    fields(b,{"identity","public_key","kem_public_key","certificate","endpoint"})
    from urllib.parse import urlparse
    require(isinstance(b["endpoint"],str) and len(b["endpoint"])<=512,"BUNDLE_ENDPOINT")
    endpoint=urlparse(b["endpoint"])
    try:port=endpoint.port
    except ValueError as e:raise MeshError("BUNDLE_ENDPOINT") from e
    require(endpoint.scheme=="https" and bool(endpoint.hostname)
            and endpoint.hostname not in {"0.0.0.0","::"}
            and endpoint.username is None and endpoint.password is None
            and not endpoint.query and not endpoint.fragment
            and endpoint.path in {"","/"} and port is not None and 1<=port<=65535,"BUNDLE_ENDPOINT")
    id=verify(b["public_key"],b"BTX/PeerBundle/1\x00"+encode(b),bundle["signature"])
    require(id==b["identity"],"BUNDLE_IDENTITY")
    # Bind the TLS certificate's key to the signing identity, not only to a PEM blob.
    with tempfile.TemporaryDirectory() as td:
        c,p=Path(td)/"cert",Path(td)/"pub";atomic_write(c,b["certificate"].encode())
        raw=run(["x509","-in",str(c),"-pubkey","-noout"]);atomic_write(p,raw)
        derived=byte_id(run(["pkey","-pubin","-in",str(p),"-outform","DER"]))
        require(derived==id,"CERTIFICATE_KEY_BINDING")
    return b


def make_invitation(identity,target_bundle,payload:dict,ttl_seconds=86400):
    target=check_bundle(target_bundle);require(1<=ttl_seconds<=604800,"INVITE_TTL")
    header={"version":1,"issuer":identity.id,"recipient":target["identity"],"nonce":os.urandom(24).hex(),"expires_ms":int(time.time()*1000)+ttl_seconds*1000}
    aad=encode(header)
    with tempfile.TemporaryDirectory(dir=identity.directory) as td:
        pub,ct,secret=[Path(td)/x for x in ("pub","ct","secret")]
        atomic_write(pub,target["kem_public_key"].encode())
        run(["pkeyutl","-encap","-pubin","-inkey",str(pub),"-out",str(ct),"-secret",str(secret)])
        key=HKDF(algorithm=hashes.SHA384(),length=32,salt=None,info=b"BTX/Invitation/1\x00"+aad).derive(secret.read_bytes())
        nonce=os.urandom(12)
        body={"header":header,"kem_ciphertext":base64.b64encode(ct.read_bytes()).decode(),"ciphertext":base64.b64encode(nonce+AESGCM(key).encrypt(nonce,encode(payload),aad)).decode()}
        return {"body":body,"issuer_public_key":identity.public,"signature":identity.sign_bytes(b"BTX/InvitationSignature/1\x00"+encode(body))}


def open_invitation(identity,invitation,pinned_issuer:str,used_nonces:set):
    fields(invitation,{"body","issuer_public_key","signature"})
    b=invitation["body"];fields(b,{"header","kem_ciphertext","ciphertext"});h=b["header"]
    fields(h,{"version","issuer","recipient","nonce","expires_ms"})
    sender=verify(invitation["issuer_public_key"],b"BTX/InvitationSignature/1\x00"+encode(b),invitation["signature"])
    require(sender==pinned_issuer==h["issuer"],"INVITE_ISSUER")
    require(h["version"]==1 and h["recipient"]==identity.id,"INVITE_RECIPIENT")
    require(h["expires_ms"]>=int(time.time()*1000),"INVITE_EXPIRED")
    require(h["nonce"] not in used_nonces,"INVITE_REPLAY")
    keypath,_=kem_keys(identity)
    with tempfile.TemporaryDirectory(dir=identity.directory) as td:
        ct,secret=Path(td)/"ct",Path(td)/"secret"
        try:rawct=base64.b64decode(b["kem_ciphertext"],validate=True);cipher=base64.b64decode(b["ciphertext"],validate=True)
        except ValueError as e:raise MeshError("INVITE_ENCODING") from e
        require(len(rawct)==1088 and 28<=len(cipher)<=1024*1024,"INVITE_SIZE")
        atomic_write(ct,rawct)
        run(["pkeyutl","-decap","-inkey",str(keypath),"-in",str(ct),"-secret",str(secret)])
        aad=encode(h);key=HKDF(algorithm=hashes.SHA384(),length=32,salt=None,info=b"BTX/Invitation/1\x00"+aad).derive(secret.read_bytes())
        try:plaintext=AESGCM(key).decrypt(cipher[:12],cipher[12:],aad)
        except Exception as e:raise MeshError("INVITE_AUTH") from e
        used_nonces.add(h["nonce"])
        return decode(plaintext)
