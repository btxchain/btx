"""Independent encrypted foreign-chain keys. NEVER accepts or derives a BTX seed.

Use in the signer authority, not the network parser process. Python cannot promise
locked-memory or complete secret zeroization; production packaging must retain this
process boundary or use a hardware/external signer.
"""
import os
import json
import hashlib
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from .canonical import digest,hex32
from .errors import require,SwapError

AAD=b'BTX/SWAPNET/FOREIGN-KEY-VAULT/1'

def atomic_private_write(path,raw):
    path=Path(path);path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    require(not path.is_symlink(),'VAULT_PATH','Vault symlink refused')
    if os.name!='nt':
        require(path.parent.stat().st_uid==os.getuid() and not path.parent.stat().st_mode&0o077,
                'VAULT_PERMISSIONS','Vault directory must be private')
    fd,tmp=tempfile.mkstemp(prefix='.swapnet-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        if os.name!='nt':
            dfd=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
            try:os.fsync(dfd)
            finally:os.close(dfd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

class ForeignKeyVault:
    def __init__(self,path,passphrase):
        self.path=Path(path)
        require(type(passphrase) is bytes and len(passphrase)>=16,'PASSPHRASE','Use a high-entropy passphrase of at least 16 bytes')
        self._passphrase=passphrase
        self.entries={}
        if self.path.exists():self._load()
    def _derive(self,salt):return Scrypt(salt=salt,length=32,n=32768,r=8,p=1).derive(self._passphrase)
    def _load(self):
        require(not self.path.is_symlink(),'VAULT_PATH','Symlink refused')
        if os.name!='nt':require(not self.path.stat().st_mode&0o077,'VAULT_PERMISSIONS','Vault must be 0600')
        raw=self.path.read_bytes();require(len(raw)<=1_000_000,'VAULT_LIMIT','Vault exceeds limit')
        try:
            envelope=json.loads(raw)
            require(set(envelope)=={'version','salt','nonce','ciphertext'} and envelope['version']==1,'VAULT_VERSION','Unknown vault version')
            salt=bytes.fromhex(envelope['salt']);nonce=bytes.fromhex(envelope['nonce'])
            require(len(salt)==16 and len(nonce)==12,'VAULT_FORMAT','Malformed vault')
            plaintext=AESGCM(self._derive(salt)).decrypt(nonce,bytes.fromhex(envelope['ciphertext']),AAD)
            self.entries=json.loads(plaintext)
        except SwapError:raise
        except Exception as e:raise SwapError('VAULT_UNLOCK','Vault authentication failed') from e
    def save(self):
        salt=os.urandom(16);nonce=os.urandom(12)
        ciphertext=AESGCM(self._derive(salt)).encrypt(nonce,json.dumps(self.entries,sort_keys=True,separators=(',',':')).encode(),AAD)
        atomic_private_write(self.path,json.dumps({'version':1,'salt':salt.hex(),'nonce':nonce.hex(),'ciphertext':ciphertext.hex()},sort_keys=True).encode())
    def create_key(self,family,genesis,role):
        require(family in {'btc','evm'},'KEY_FAMILY','BTX keys never enter foreign vault')
        hex32(genesis);require(role in {'claim','refund','funding'},'KEY_ROLE','Unknown role')
        key=ec.generate_private_key(ec.SECP256K1())
        kid=digest('BTX/SWAPNET/FOREIGN-KEY/1',{'family':family,'genesis':genesis,'role':role,'nonce':os.urandom(32).hex()})
        self.entries[kid]={'family':family,'genesis':genesis,'role':role,'scalar':format(key.private_numbers().private_value,'064x')}
        self.save();return kid
    def key(self,kid,*,family,genesis,role):
        require(kid in self.entries,'KEY_MISSING','Key not found')
        entry=self.entries[kid]
        require((entry['family'],entry['genesis'],entry['role'])==(family,genesis,role),'SIGNER_SCOPE','Key is bound to another chain or role')
        return ec.derive_private_key(int(entry['scalar'],16),ec.SECP256K1())
    def public_key(self,kid,*,family,genesis,role):
        return self.key(kid,family=family,genesis=genesis,role=role).public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)

    def new_secret(self,swap_id):
        hex32(swap_id);sid='secret_'+swap_id
        require(sid not in self.entries,'SECRET_EXISTS','Never replace an existing swap secret')
        secret=os.urandom(32)
        self.entries[sid]={'swap_id':swap_id,'preimage':secret.hex()}
        self.save()
        return hashlib.sha256(secret).hexdigest()
    def secret(self,swap_id,expected_hashlock):
        hex32(swap_id);hex32(expected_hashlock)
        e=self.entries.get('secret_'+swap_id)
        require(e is not None and e.get('swap_id')==swap_id,'SECRET_MISSING','Swap secret missing')
        secret=bytes.fromhex(e['preimage'])
        require(len(secret)==32 and hashlib.sha256(secret).hexdigest()==expected_hashlock,'HASHLOCK','Wrong secret scope')
        return secret
