#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Stage an explicit application-local CPython distribution; never download it."""
from pathlib import Path
import importlib.util
import re
import shutil
import struct
import zipfile


def verifier():
    spec = importlib.util.spec_from_file_location('windows_bundle_verify', Path(__file__).with_name('verify_release_btxd.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_x64(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:2] != b'MZ':
        raise RuntimeError(f'Not a PE runtime image: {path.name}')
    offset = struct.unpack_from('<I', data, 60)[0]
    if offset + 6 > len(data) or data[offset:offset+4] != b'PE\0\0' or struct.unpack_from('<H', data, offset+4)[0] != 0x8664:
        raise RuntimeError(f'Runtime image must be x64: {path.name}')


def bundle_windows_python(release_root, runtime):
    """runtime is a prepared official embeddable distribution plus pinned wheels.

    The producer verifies its source hashes. No host installation, registry or
    user-site paths are copied or added to the isolated module search path.
    """
    root = Path(release_root)
    binary = root / 'bin/btxd.exe'
    verify = verifier()
    if verify.classify(binary) != "pe":
        return []  # The caller's unchanged shipping gate rejects untyped inputs.
    imports = verify.pe_imports(binary)
    names = [name for name in imports if re.fullmatch(r'python3\d+\.dll', name, re.I)]
    if not names:
        if any(name.lower().startswith('python') for name in imports):
            raise RuntimeError('Unsupported Python runtime ABI')
        if b'SwapNet Python initialization failed' in binary.read_bytes():
            raise RuntimeError('SwapNet has no supported shared Python DLL import')
        return []
    if len(names) != 1:
        raise RuntimeError('Ambiguous Python runtime ABI')
    if runtime is None:
        raise RuntimeError('Windows SwapNet requires --windows-python-runtime with matching embeddable Python and pinned dependencies')
    source = Path(runtime)
    dll = names[0].lower()
    stem = dll[:-4]
    if not (source / dll).is_file() or not (source / (stem + '.zip')).is_file():
        raise RuntimeError('Embeddable runtime does not match the linked Python ABI')
    if not (source / 'LICENSE.txt').is_file():
        raise RuntimeError('Python runtime licence is missing')
    site = source / 'Lib/site-packages'
    if not (site / 'cryptography/__init__.py').is_file():
        raise RuntimeError('Pinned cryptography package is missing')
    native_crypto = list((site / 'cryptography/hazmat/bindings').glob('_rust*.pyd'))
    if len(native_crypto) != 1:
        raise RuntimeError('Native cryptography package is missing or ambiguous')
    native_cffi = list(site.glob('_cffi_backend*.pyd'))
    if len(native_cffi) != 1:
        raise RuntimeError('Native CFFI package is missing or ambiguous')
    metadata = list(site.glob('cryptography-*.dist-info/METADATA'))
    if len(metadata) != 1 or '\nVersion: 46.0.4\n' not in ('\n' + metadata[0].read_text()):
        raise RuntimeError('cryptography must match the tested runtime pin 46.0.4')
    with zipfile.ZipFile(source / (stem + '.zip')) as stdlib:
        if 'encodings/__init__.pyc' not in stdlib.namelist() or 'os.pyc' not in stdlib.namelist():
            raise RuntimeError('Embeddable standard library is incomplete')
    files = []
    for path in source.rglob('*'):
        if path.is_symlink():
            raise RuntimeError('Runtime symlinks are unsupported')
        if not path.is_file():
            continue
        rel = path.relative_to(source)
        if len(rel.parts) == 1:
            if path.suffix.lower() not in {'.dll', '.pyd'} and path.name not in {'LICENSE.txt', 'python.exe', stem + '.zip'}:
                continue
        elif rel.parts[:2] != ('Lib', 'site-packages'):
            continue
        if '__pycache__' not in rel.parts:
            files.append((path, rel))
    if len(files) > 5000 or sum(p.stat().st_size for p, _ in files) > 150 * 1024**2:
        raise RuntimeError('Runtime input exceeds the supported package bound')
    out = root / 'bin'
    included = []
    def put(src, dst):
        if dst.exists() and dst.read_bytes() != src.read_bytes():
            raise RuntimeError(f'Conflicting runtime destination: {dst.name}')
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        included.append(str(dst.relative_to(root)))
    for src, rel in files:
        if src.suffix.lower() in {'.exe', '.dll', '.pyd'}:
            require_x64(src)
        put(src, out / rel)
    (out / (stem + '._pth')).write_text(stem + '.zip\n.\nLib/site-packages\n', encoding='utf-8')
    included.append('bin/' + stem + '._pth')
    # Match the existing adjacent-import gate for native package extensions.
    # Aliases are exact bytes from the explicit runtime root, never host DLLs.
    images = [out / rel for _, rel in files if rel.suffix.lower() in {'.exe', '.dll', '.pyd'}]
    pending = list(images)
    checked = set()
    while pending:
        image = pending.pop()
        if image in checked:
            continue
        checked.add(image)
        for name in verify.pe_imports(image):
            if name.lower() in verify.WINDOWS_SYSTEM_DLLS or name.lower().startswith(('api-ms-win-', 'ext-ms-')):
                continue
            candidate = next((p for p in out.iterdir() if p.is_file() and p.name.lower() == name.lower()), None)
            sibling = image.parent / name
            if sibling.is_file():
                if candidate is not None and sibling.read_bytes() != candidate.read_bytes():
                    raise RuntimeError(f'Conflicting runtime dependency: {name}')
                continue
            if candidate is None:
                raise RuntimeError(f'Runtime dependency is missing: {name}')
            alias = image.parent / name
            put(candidate, alias)
            pending.append(alias)
    problems = verify.pe_problems(root, sorted(checked))
    if problems:
        raise RuntimeError('; '.join(problems))
    return sorted(set(included))


def bundle_windows_openmp(release_root, runtime):
    """Stage one explicitly supplied LLVM runtime under the linked MSVC name.

    LLVM's OPENMP_MSVC_NAME_SCHEME uses this filename for the same runtime.
    The producer must verify the official payload, licence and imported symbols.
    Never discover a host Visual Studio debug_nonredist runtime implicitly.
    """
    root = Path(release_root)
    verify = verifier()
    images = [p for p in (root / 'bin').glob('*.exe') if verify.classify(p) == 'pe']
    names = {name.lower() for p in images for name in verify.pe_imports(p)
             if name.lower().startswith('libomp')}
    if not names:
        return []
    if names != {'libomp140.x86_64.dll'}:
        raise RuntimeError('Unsupported or mixed OpenMP runtime names')
    if runtime is None:
        raise RuntimeError('Linked OpenMP requires --windows-openmp-runtime')
    source = Path(runtime)
    dll = source / 'libomp.dll'
    licence = source / 'LICENSE.txt'
    if dll.is_symlink() or licence.is_symlink() or not dll.is_file() or not licence.is_file():
        raise RuntimeError('Explicit LLVM runtime and licence are required')
    require_x64(dll)
    destination = root / 'bin/libomp140.x86_64.dll'
    if any(p.name.lower().startswith('libomp') and p.name.lower() != destination.name.lower()
           for p in (root / 'bin').iterdir()):
        raise RuntimeError('Multiple OpenMP runtime copies are unsupported')
    if destination.exists() and destination.read_bytes() != dll.read_bytes():
        raise RuntimeError('Conflicting OpenMP runtime destination')
    shutil.copy2(dll, destination)
    notice = root / 'share/licenses/llvm-openmp/LICENSE.txt'
    notice.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(licence, notice)
    problems = verify.pe_problems(root, [destination])
    if problems:
        raise RuntimeError('; '.join(problems))
    return [str(destination.relative_to(root)), str(notice.relative_to(root))]
