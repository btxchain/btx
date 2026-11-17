"""OS protection for a NEW Windows vault wrapping key; legacy keys are not silently migrated.

DPAPI protects against copying the protected blob to another user context. It is
not protection from a compromised logged-in account, administrator, or node.
Encrypted recovery exports remain the portable backup mechanism.
"""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import secrets
from .market_controls import require

class DataBlob(ctypes.Structure):
 _fields_=[('cbData',wintypes.DWORD),('pbData',ctypes.POINTER(ctypes.c_ubyte))]

def dpapi(data:bytes,protect:bool)->bytes:
 require(os.name=='nt','PLATFORM','DPAPI is available only on Windows')
 require(type(data) is bytes and 0<len(data)<=65536,'VAULT_FORMAT','Invalid DPAPI input')
 crypt32=ctypes.WinDLL('crypt32',use_last_error=True);kernel32=ctypes.WinDLL('kernel32',use_last_error=True)
 backing=(ctypes.c_ubyte*len(data)).from_buffer_copy(data);source=DataBlob(len(data),ctypes.cast(backing,ctypes.POINTER(ctypes.c_ubyte)));out=DataBlob()
 # CRYPTPROTECT_UI_FORBIDDEN. Never set CRYPTPROTECT_LOCAL_MACHINE.
 if protect:
  fn=crypt32.CryptProtectData;fn.argtypes=[ctypes.POINTER(DataBlob),wintypes.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(DataBlob)]
  ok=fn(ctypes.byref(source),'BTX SwapNet vault wrapping key',None,None,None,1,ctypes.byref(out))
 else:
  fn=crypt32.CryptUnprotectData;fn.argtypes=[ctypes.POINTER(DataBlob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(DataBlob)]
  ok=fn(ctypes.byref(source),None,None,None,None,1,ctypes.byref(out))
 fn.restype=wintypes.BOOL
 require(bool(ok),'VAULT_OS_PROTECTION',f'DPAPI operation failed ({ctypes.get_last_error()})')
 try:return ctypes.string_at(out.pbData,out.cbData)
 finally:
  kernel32.LocalFree.argtypes=[ctypes.c_void_p];kernel32.LocalFree.restype=ctypes.c_void_p;kernel32.LocalFree(out.pbData)

def load_master(directory:Path,atomic_write):
 """Returns (key, protection label). Never writes an unprotected NEW Windows key."""
 legacy=directory/'vault.key';protected=directory/'vault.key.dpapi'
 require(not legacy.is_symlink() and not protected.is_symlink(),'VAULT_PATH','Symlink wrapping keys refused')
 if protected.exists():
  require(os.name=='nt','VAULT_OS_PROTECTION','Restore an encrypted recovery bundle on this operating system')
  key=dpapi(protected.read_bytes(),False)
  if legacy.exists():require(secrets.compare_digest(key,legacy.read_bytes()),'VAULT_CONFLICT','Protected and legacy keys differ')
  require(len(key)==32,'VAULT_FORMAT','Wrong wrapping key length')
  return key,'windows-user-dpapi-with-legacy-copy' if legacy.exists() else 'windows-user-dpapi'
 if legacy.exists():
  if os.name!='nt':require(legacy.stat().st_uid==os.getuid() and not legacy.stat().st_mode&0o077,'VAULT_PERMISSIONS','Wrapping key must be private')
  key=legacy.read_bytes();require(len(key)==32,'VAULT_FORMAT','Wrong wrapping key length')
  return key,'legacy-local-owner-filesystem'
 key=secrets.token_bytes(32)
 if os.name=='nt':atomic_write(protected,dpapi(key,True));return key,'windows-user-dpapi'
 atomic_write(legacy,key);return key,'local-owner-filesystem'
