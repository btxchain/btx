"""Owner-private financial storage without changing the portable backup format.

Windows uses a protected DACL for the current user and SYSTEM, with inherited
rights for new files. No DPAPI blob replaces vault.key: encrypted recovery
bundles therefore retain their existing portable format.
"""
from __future__ import annotations
import os
from pathlib import Path
from .errors import require,SwapError


def protect_private_directory(directory):
    path=Path(directory)
    require(path.is_dir() and not path.is_symlink(),'VAULT_PATH','Private storage must be a real directory')
    if os.name!='nt':
        stat=path.stat();require(stat.st_uid==os.getuid(),'VAULT_PERMISSIONS','Storage owner differs')
        os.chmod(path,0o700);return
    import ctypes
    from ctypes import wintypes
    adv=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    HANDLE=wintypes.HANDLE;DWORD=wintypes.DWORD;LPVOID=ctypes.c_void_p
    adv.OpenProcessToken.argtypes=[HANDLE,DWORD,ctypes.POINTER(HANDLE)];adv.OpenProcessToken.restype=wintypes.BOOL
    adv.GetTokenInformation.argtypes=[HANDLE,ctypes.c_int,LPVOID,DWORD,ctypes.POINTER(DWORD)];adv.GetTokenInformation.restype=wintypes.BOOL
    adv.ConvertSidToStringSidW.argtypes=[LPVOID,ctypes.POINTER(wintypes.LPWSTR)];adv.ConvertSidToStringSidW.restype=wintypes.BOOL
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[wintypes.LPCWSTR,DWORD,ctypes.POINTER(LPVOID),ctypes.POINTER(DWORD)];adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=wintypes.BOOL
    adv.GetNamedSecurityInfoW.argtypes=[wintypes.LPWSTR,ctypes.c_int,DWORD,ctypes.POINTER(LPVOID),LPVOID,LPVOID,LPVOID,ctypes.POINTER(LPVOID)];adv.GetNamedSecurityInfoW.restype=DWORD
    adv.SetFileSecurityW.argtypes=[wintypes.LPCWSTR,DWORD,LPVOID];adv.SetFileSecurityW.restype=wintypes.BOOL
    kernel.GetCurrentProcess.restype=HANDLE;kernel.LocalFree.argtypes=[LPVOID];kernel.LocalFree.restype=LPVOID
    kernel.CloseHandle.argtypes=[HANDLE];kernel.CloseHandle.restype=wintypes.BOOL
    kernel.GetFileAttributesW.argtypes=[wintypes.LPCWSTR];kernel.GetFileAttributesW.restype=DWORD
    token=HANDLE();require(adv.OpenProcessToken(kernel.GetCurrentProcess(),0x0008,ctypes.byref(token)),'VAULT_PERMISSIONS','Cannot obtain current user token')
    def sid_string(sid):
        text=wintypes.LPWSTR()
        require(adv.ConvertSidToStringSidW(sid,ctypes.byref(text)),'VAULT_PERMISSIONS','Cannot identify storage owner')
        try:return text.value
        finally:kernel.LocalFree(ctypes.cast(text,LPVOID))
    try:
        required=DWORD();adv.GetTokenInformation(token,1,None,0,ctypes.byref(required))
        require(0<required.value<65536,'VAULT_PERMISSIONS','Invalid user token size')
        buffer=ctypes.create_string_buffer(required.value)
        require(adv.GetTokenInformation(token,1,buffer,required,ctypes.byref(required)),'VAULT_PERMISSIONS','Cannot read user token')
        sid=ctypes.cast(buffer,ctypes.POINTER(LPVOID))[0];current=sid_string(sid)
    finally:kernel.CloseHandle(token)
    descriptor=LPVOID()
    sddl=f'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{current})'
    require(adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(descriptor),None),
            'VAULT_PERMISSIONS','Cannot construct private storage ACL')
    try:
        files=[path]+[p for p in path.rglob('*') if p.name in {'state.sqlite','state.sqlite-wal','state.sqlite-shm','vault.key','foreign-vault.json'} or p.suffix=='.snr' or p.is_dir()]
        for entry in files:
            name=str(entry.absolute());attributes=kernel.GetFileAttributesW(name)
            require(attributes!=0xffffffff and not attributes&0x400,'VAULT_PATH','Reparse points are forbidden in private storage')
            owner=LPVOID();old_descriptor=LPVOID()
            rc=adv.GetNamedSecurityInfoW(name,1,1,ctypes.byref(owner),None,None,None,ctypes.byref(old_descriptor))
            require(rc==0,'VAULT_PERMISSIONS','Cannot check storage owner')
            try:require(sid_string(owner)==current,'VAULT_PERMISSIONS','Private storage belongs to another account')
            finally:kernel.LocalFree(old_descriptor)
            require(adv.SetFileSecurityW(name,0x00000004|0x80000000,descriptor),
                    'VAULT_PERMISSIONS','Cannot enforce a protected private storage ACL')
    finally:kernel.LocalFree(descriptor)
