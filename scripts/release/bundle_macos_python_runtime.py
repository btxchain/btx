#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see COPYING.
"""Stage the linked CPython framework and SwapNet imports in a relocatable Mac archive.

Reuse the import inventory/stdlib exclusions from Jpp-matata's Linux runtime bundler (#678).
Only copies in the release tree are rewritten and ad-hoc signed. Developer ID
signing/notarization remains a later release operation.
"""
from __future__ import annotations
import importlib.util
from functools import lru_cache
import json
import os
import posixpath
import plistlib
from pathlib import Path
import re
import shutil
import subprocess

PYTHON = re.compile(r'(?:^|/)(?:Python\.framework/)?Versions/(3\.\d+)/Python$')
SYSTEM = ('/usr/lib/', '/System/Library/')
MAGIC = {b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}


@lru_cache(maxsize=None)
def helper(name):
    spec = importlib.util.spec_from_file_location('mac_bundle_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def system_load(name):
    return name.startswith('/') and posixpath.normpath(name).startswith(SYSTEM)


def executable_directory(owner):
    for parent in owner.parents:
        if parent.suffix == '.app':
            info = parent / 'Contents/Info.plist'
            with info.open('rb') as stream:
                name = plistlib.load(stream)['CFBundleExecutable']
            exe = parent / 'Contents/MacOS' / name
            if not exe.is_file() or not within(exe, parent):
                raise RuntimeError('App executable is missing or escapes its bundle')
            return exe.parent
    if owner.parent.name in {'bin', 'libexec'}:
        return owner.parent
    raise RuntimeError(f'No executable context for {owner}')


def macho(path):
    if not path.is_file() or path.is_symlink():
        return False
    with path.open('rb') as stream:
        return stream.read(4) in MAGIC


def loads(path):
    return helper('verify_release_btxd').macho_dylibs(path)


def within(path, root):
    return path.resolve().is_relative_to(root.resolve())


def copy_file(source, target):
    if target.exists():
        if target.read_bytes() != source.read_bytes():
            raise RuntimeError(f'Conflicting runtime file: {target}')
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def copy_package(source, target, linux):
    if source.is_symlink():
        raise RuntimeError(f'Unsupported root package symlink: {source}')
    if source.is_dir():
        for item in source.rglob('*'):
            if item.is_symlink() and (item.is_dir() or not within(item, source)):
                raise RuntimeError(f'Unsupported escaping/directory package symlink: {item}')
    linux._copy_tree(source, target)


def relative_load(owner, target):
    return '@loader_path/' + os.path.relpath(target, owner.parent)


def verify_closure(paths, root):
    verify = helper('verify_release_btxd')
    for path in paths:
        verify.verify_macos_portable(path)
        deps, rpaths = verify.macho_load_paths(path)
        def relative_target(name):
            if name.startswith('@loader_path/'):
                return path.parent / name[len('@loader_path/'):]
            if name.startswith('@executable_path/'):
                return executable_directory(path) / name[len('@executable_path/'):]
            if name in {'@loader_path', '@executable_path'}:
                return path.parent if name == '@loader_path' else executable_directory(path)
            raise RuntimeError(f'Unexpected runtime search path in {path}: {name}')
        search = []
        for entry in rpaths:
            if system_load(entry):
                continue
            directory = relative_target(entry)
            if not directory.is_dir() or not within(directory, root):
                raise RuntimeError(f'Runtime search path escapes/is missing in {path}: {entry}')
            search.append(directory)
        for dep in deps:
            if system_load(dep):
                continue
            if dep.startswith('@rpath/'):
                targets = {str((d / dep[len('@rpath/'):]).resolve()) for d in search
                           if (d / dep[len('@rpath/'):]).is_file()}
                if len(targets) != 1:
                    raise RuntimeError(f'Unresolved/ambiguous dependency in {path}: {dep}')
                target = Path(targets.pop())
            else:
                target = relative_target(dep)
            if not target.is_file() or not within(target, root):
                raise RuntimeError(f'Dependency escapes/is missing in {path}: {dep}')


def verify_architectures(paths, architecture):
    if architecture not in {'arm64', 'x86_64'}:
        raise RuntimeError('Unsupported Mac archive architecture')
    for path in paths:
        archs = subprocess.check_output(['lipo', '-archs', str(path)], text=True).split()
        if architecture not in archs:
            raise RuntimeError(f'Python runtime architecture mismatch in {path}: {archs}')


def bundle_macos_python(release_root, *, source_root, python=None, architecture=None):
    release_root = Path(release_root).resolve()
    initial = [p for p in release_root.rglob('*') if macho(p)]
    linked = [(p, dep, PYTHON.search(dep)) for p in initial for dep in loads(p) if PYTHON.search(dep)]
    if not linked:
        # A different libpython layout must not silently become a runtime-free archive.
        if any('libpython' in dep or dep.endswith('/Python') for p in initial for dep in loads(p)):
            raise RuntimeError('Mac Python bundling requires a CPython framework layout')
        if any(helper('bundle_python_runtime').embeds_swapnet(p) for p in initial):
            raise RuntimeError('SwapNet worker has no supported shared Python framework')
        return []
    versions = {m.group(1) for _, _, m in linked}
    if len(versions) != 1:
        raise RuntimeError('Mixed linked Python versions')
    version = versions.pop()
    python = python or shutil.which('python' + version)
    if not python:
        raise RuntimeError(f'Python {version} required to package this binary; pass --python')
    linux = helper('bundle_python_runtime')
    modules = sorted(set(linux.swapnet_imports(Path(source_root))) | {"cryptography", "_cffi_backend"})
    info = linux.probe_interpreter(str(python), modules)
    if info['version'] != version or info['failed']:
        raise RuntimeError(f'Python ABI/import mismatch: expected {version}, got {info}')
    pin = (Path(source_root) / 'contrib/swapnet/requirements-tested-runtime.txt').read_text()
    expected = re.search(r'^cryptography==([^\s]+)', pin, re.M)
    crypto = subprocess.check_output([str(python), '-I', '-c', 'import cryptography; print(cryptography.__version__)'], text=True).strip()
    if not expected or crypto != expected.group(1):
        raise RuntimeError('Packaging cryptography must match requirements-tested-runtime.txt')
    prefix = Path(info['prefix']).resolve()
    library = prefix / 'Python'
    if not library.is_file():
        raise RuntimeError('Interpreter has no matching framework library')
    # Framework layout is retained, but only real dirs/files: archive writers need no symlink support.
    destination = release_root / 'lib/Python.framework/Versions' / version
    if destination.exists():
        raise RuntimeError('Python destination already exists')
    mapping = {}
    def put(src, dst):
        src = src.resolve()
        copy_file(src, dst)
        if macho(dst):
            mapping[src] = dst
    put(library, destination / 'Python')
    # The bundled interpreter is also the isolated import-verification entry point.
    for relative in ['bin/python' + version, 'Resources/Python.app/Contents/MacOS/Python', 'Resources/Info.plist', 'Resources/Python.app/Contents/Info.plist']:
        src = prefix / relative
        if src.is_file():
            put(src, destination / relative)
    stdlib = Path(info['stdlib'])
    skipped = linux._copy_stdlib(stdlib, destination / 'lib' / ('python' + version))
    if skipped:
        raise RuntimeError(f'Unsafe/unsupported stdlib symlinks: {skipped}')
    # Unlike distro Python, framework site-packages sits INSIDE the stdlib prefix.
    roots = {}
    for name, filename in info['modules'].items():
        file = Path(filename)
        if 'site-packages' not in file.parts and 'dist-packages' not in file.parts:
            continue
        top = name.split('.')[0]
        item = Path(info['modules'].get(top, filename))
        roots[top] = item.parent if item.name.startswith('__init__.') else item
    if 'cryptography' not in roots or '_cffi_backend' not in roots:
        raise RuntimeError('SwapNet crypto native import inventory is incomplete')
    for src in roots.values():
        target = destination / 'lib' / ('python' + version) / 'site-packages' / src.name
        copy_package(src, target, linux)
    # Keep distribution attribution/licences alongside the selected third-party modules.
    wanted = {name.lower().replace('_', '-') for name in roots}
    if '_cffi_backend' in roots:
        wanted.add('cffi')
    for parent in {r.parent for r in roots.values()}:
        for metadata in parent.glob('*.dist-info'):
            manifest = metadata / 'METADATA'
            if not manifest.is_file():
                continue
            name = re.search(r'^Name: (.+)$', manifest.read_text(), re.M)
            if name and name.group(1).strip().lower().replace('_', '-') in wanted:
                copy_package(metadata, destination / 'lib' / ('python' + version) / 'site-packages' / metadata.name, linux)
    # Associate copied native files with their original locations to resolve @ paths.
    for target in destination.rglob('*'):
        if macho(target) and target not in mapping.values():
            relative = target.relative_to(destination)
            src = prefix / relative
            if not src.is_file():
                # Third-party roots may live outside sys.prefix.
                candidates = [r / target.relative_to(destination / 'lib' / ('python' + version) / 'site-packages' / r.name)
                              for r in roots.values() if r.is_dir() and target.is_relative_to(destination / 'lib' / ('python' + version) / 'site-packages' / r.name)]
                src = next((x for x in candidates if x.is_file()), None)
            if src is None or not src.is_file():
                raise RuntimeError(f'Cannot identify source for {target}')
            mapping[src.resolve()] = target
    framework_prefixes = {dep[:-len('Python')] for _, dep, _ in linked if dep.startswith('/')}
    for identity in subprocess.check_output(['otool', '-D', str(library)], text=True).splitlines():
        if PYTHON.search(identity.strip()) and identity.strip().startswith('/'):
            framework_prefixes.add(identity.strip()[:-len('Python')])
    def resolve(owner, dep):
        if PYTHON.search(dep):
            return library.resolve()
        for base in framework_prefixes:
            if dep.startswith(base):
                return (prefix / dep[len(base):]).resolve()
        if dep.startswith('@loader_path/'):
            return (owner.parent / dep[len('@loader_path/'):]).resolve()
        if dep.startswith('@executable_path/'):
            return (executable_directory(owner) / dep[len('@executable_path/'):]).resolve()
        if dep.startswith('@rpath/'):
            _, rpaths = helper('verify_release_btxd').macho_load_paths(owner)
            for entry in rpaths:
                base = entry.replace('@loader_path', str(owner.parent))
                if '@executable_path' in base:
                    base = base.replace('@executable_path', str(executable_directory(owner)))
                if base.startswith('@'):
                    continue
                candidate = Path(base) / dep[len('@rpath/'):]
                if candidate.is_file():
                    return candidate.resolve()
            raise RuntimeError(f'Unresolvable rpath dependency: {dep}')
        if dep.startswith('/'):
            return Path(dep).resolve()
        raise RuntimeError(f'Unsupported Mach-O dependency: {dep}')
    # The daemon/Qt entry points may reference the same runtime, even via @rpath.
    entry_mapping = {p: p for p in initial if any(PYTHON.search(d) for d in loads(p))}
    work = list(mapping) + list(entry_mapping)
    edits = {}
    unchanged_staged = set()
    while work:
        original = work.pop()
        target = mapping.get(original, entry_mapping.get(original))
        for dep in loads(original):
            if system_load(dep):
                continue
            resolved = resolve(original, dep)
            if not resolved.is_file():
                raise RuntimeError(f'Missing native runtime dependency: {dep}')
            if resolved not in mapping and within(resolved, release_root):
                # macdeployqt already staged this non-Python dependency. Preserve its signature/rpaths.
                mapping[resolved] = resolved
                unchanged_staged.add(resolved)
            if resolved not in mapping:
                dst = destination / resolved.relative_to(prefix) if within(resolved, prefix) else release_root / 'lib/python-private' / resolved.name
                put(resolved, dst)
                work.append(resolved)
            edits.setdefault(target, []).append((dep, relative_load(target, mapping[resolved])))
    staged = (set(mapping.values()) - unchanged_staged) | set(entry_mapping)
    for target in sorted(staged):
        # Drop build-host lookup paths; all non-system loads are now explicit relative paths.
        for entry in helper('verify_release_btxd').macho_load_paths(target)[1]:
            subprocess.run(['install_name_tool', '-delete_rpath', entry, str(target)], check=True, capture_output=True)
        for old, new in edits.get(target, []):
            subprocess.run(['install_name_tool', '-change', old, new, str(target)], check=True, capture_output=True)
        subprocess.run(['codesign', '--force', '--sign', '-', str(target)], check=True, capture_output=True)
    # Re-seal any app whose executable was edited after macdeployqt.
    for app in sorted(release_root.rglob('*.app'), key=lambda p: len(p.parts), reverse=True):
        if any(p.is_relative_to(app) for p in staged):
            subprocess.run(['codesign', '--force', '--sign', '-', str(app)], check=True, capture_output=True)
    # Framework resource seals must be created after signing nested app executables.
    subprocess.run(['codesign', '--force', '--sign', '-', str(destination / 'Python')], check=True, capture_output=True)
    if architecture is not None:
        verify_architectures(staged, architecture)
    verify_closure(staged, release_root)
    # No DYLD/PYTHON env. Validate the same relocated framework/std/native imports that ship.
    exe = destination / 'bin' / ('python' + version)
    env = {'PATH': '/usr/bin:/bin'}
    probe = subprocess.run([str(exe), '-I', '-B', '-c', linux.PROBE, json.dumps(modules)], env=env, capture_output=True, text=True)
    if probe.returncode:
        raise RuntimeError('Staged Python import check failed: ' + probe.stderr)
    staged_info = json.loads(probe.stdout)
    if staged_info['failed'] or not within(Path(staged_info['prefix']), release_root):
        raise RuntimeError('Staged Python import closure/prefix is invalid')
    for filename in staged_info['modules'].values():
        if not within(Path(filename), release_root):
            raise RuntimeError('Staged interpreter imported outside the archive: ' + filename)
    return [str(p.relative_to(release_root)) for p in destination.rglob('*') if p.is_file()] + [str(p.relative_to(release_root)) for p in staged if not p.is_relative_to(destination)]
