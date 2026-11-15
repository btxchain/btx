#!/usr/bin/env python3
"""Portable fail-closed rules; native archive fixture qualifies loader/signature behavior."""
import importlib.util
from pathlib import Path
import tempfile
import plistlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bundle_macos_python_runtime', ROOT / 'scripts/release/bundle_macos_python_runtime.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class MacRuntimeTest(unittest.TestCase):
    def test_system_paths_are_normalized(self):
        self.assertTrue(m.system_load('/usr/lib/libSystem.B.dylib'))
        self.assertFalse(m.system_load('/usr/lib/../local/lib/foreign.dylib'))
        self.assertFalse(m.system_load('/System/Library/../../Library/Frameworks/foreign'))

    def test_app_executable_context_is_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            app=Path(d)/'Qt.app';exe=app/'Contents/MacOS/btx-qt';exe.parent.mkdir(parents=True);exe.write_bytes(b'fixture')
            (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'btx-qt'}))
            self.assertEqual(m.executable_directory(app/'Contents/Frameworks/QtCore'),exe.parent)
            (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'../../../../outside'}))
            with self.assertRaises(RuntimeError):m.executable_directory(app/'Contents/Frameworks/QtCore')

    def test_runtime_architecture_must_include_target(self):
        with patch.object(m.subprocess, 'check_output', return_value='arm64 x86_64'):
            m.verify_architectures([Path('fixture')], 'arm64')
        with patch.object(m.subprocess, 'check_output', return_value='x86_64'):
            with self.assertRaisesRegex(RuntimeError, 'architecture mismatch'):
                m.verify_architectures([Path('fixture')], 'arm64')
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            m.verify_architectures([], 'unknown')

    def test_framework_layouts(self):
        for name in ['/Library/Frameworks/Python.framework/Versions/3.12/Python', '/producer/Versions/3.12/Python', '@rpath/Python.framework/Versions/3.12/Python']:
            self.assertEqual(m.PYTHON.search(name).group(1), '3.12')
        self.assertIsNone(m.PYTHON.search('/System/Library/not-python'))

    def test_copy_collision_refuses_changed_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d);a=p/'a';b=p/'b';a.write_bytes(b'old');b.write_bytes(b'new')
            with self.assertRaisesRegex(RuntimeError, 'Conflicting'):m.copy_file(a,b)
            self.assertEqual(b.read_bytes(), b'new')
            a.write_bytes(b'new');m.copy_file(a,b)

    def test_symlink_escape_and_directory_alias_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);source=p/'package';source.mkdir();outside=p/'outside';outside.write_text('not package data');link=source/'data';link.symlink_to(outside)
            copy=SimpleNamespace(_copy_tree=lambda *a:self.fail('copied unsafe data'))
            alias=p/'alias.dist-info';alias.symlink_to(source,target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError,'root package symlink'):m.copy_package(alias,p/'out',copy)
            with self.assertRaisesRegex(RuntimeError,'symlink'):m.copy_package(source,p/'out',copy)
            link.unlink();link.symlink_to(source, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError,'symlink'):m.copy_package(source,p/'out',copy)

    def test_closure_resolves_only_existing_bounded_relative_files(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'root';root.mkdir();owner=root/'binary';owner.write_text('fixture');lib=root/'lib';lib.write_text('fixture');outside=Path(d)/'outside';outside.write_text('fixture')
            rules=SimpleNamespace(verify_macos_portable=lambda p:None,macho_load_paths=lambda p:(['@loader_path/lib'],[]))
            with patch.object(m,'helper',return_value=rules):m.verify_closure([owner],root)
            for dep in ['@loader_path/missing','@loader_path/../outside','/producer/libPython','@rpath/libPython']:
                rules.macho_load_paths=lambda p,dep=dep:([dep],[])
                with patch.object(m,'helper',return_value=rules),self.assertRaises(RuntimeError):m.verify_closure([owner],root)
            rules.macho_load_paths=lambda p:([],['/producer/library'])
            with patch.object(m,'helper',return_value=rules),self.assertRaisesRegex(RuntimeError,'search path'):m.verify_closure([owner],root)

    def test_worker_without_shared_framework_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'daemon').write_bytes(b'fixture')
            rules=SimpleNamespace(embeds_swapnet=lambda p:True)
            with patch.object(m,'macho',return_value=True),patch.object(m,'loads',return_value=[]),patch.object(m,'helper',return_value=rules):
                with self.assertRaisesRegex(RuntimeError,'no supported shared'):m.bundle_macos_python(root,source_root=root)

    def test_wrong_abi_and_failed_import_refused_before_copy(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'daemon').write_bytes(b'fixture')
            for info in [{'version':'3.11','failed':[]},{'version':'3.12','failed':['crypto']}]:
                rules=SimpleNamespace(swapnet_imports=lambda p:[],probe_interpreter=lambda *a:info)
                with patch.object(m,'macho',return_value=True),patch.object(m,'loads',return_value=['/Library/Frameworks/Python.framework/Versions/3.12/Python']),patch.object(m,'helper',return_value=rules):
                    with self.assertRaisesRegex(RuntimeError,'ABI/import mismatch'):m.bundle_macos_python(root,source_root=root,python='python')

    def test_standalone_native_module_outside_framework_is_relocated(self):
        import shutil
        import json
        with tempfile.TemporaryDirectory() as d:
            base = Path(d).resolve()
            root = base / "release"
            root.mkdir()
            daemon = root / "libexec/btxd.real"
            daemon.parent.mkdir()
            magic = b"\xcf\xfa\xed\xfe"
            daemon.write_bytes(magic)
            prefix = base / "producer/Python.framework/Versions/3.12"
            prefix.mkdir(parents=True)
            (prefix / "Python").write_bytes(magic)
            stdlib = prefix / "lib/python3.12"
            stdlib.mkdir(parents=True)
            site = base / "external/site-packages"
            crypto = site / "cryptography/__init__.py"
            crypto.parent.mkdir(parents=True)
            crypto.write_text("# fixture")
            cffi = site / "_cffi_backend.cpython-312-darwin.so"
            cffi.write_bytes(magic)
            source = base / "source/contrib/swapnet"
            source.mkdir(parents=True)
            (source / "requirements-tested-runtime.txt").write_text("cryptography==46.0.4\n")
            def copy_tree(src, dst):
                if src.is_dir(): shutil.copytree(src, dst, dirs_exist_ok=True)
                else:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
            info = {"version":"3.12", "failed":[], "prefix":str(prefix),
                    "stdlib":str(stdlib), "modules":{"cryptography":str(crypto), "_cffi_backend":str(cffi)}}
            linux = SimpleNamespace(swapnet_imports=lambda p:[], probe_interpreter=lambda *a:info,
                _copy_stdlib=lambda *a:[], _copy_tree=copy_tree, PROBE="fixture")
            verifier = SimpleNamespace(macho_load_paths=lambda p:([],[]), verify_macos_portable=lambda p:None)
            destination = root / "lib/Python.framework/Versions/3.12"
            def run(args, **kwargs):
                return SimpleNamespace(returncode=0, stdout=json.dumps({"failed":[], "prefix":str(destination),
                    "modules":{"_cffi_backend":str(destination / "lib/python3.12/site-packages" / cffi.name)}}), stderr="")
            with patch.object(m, "helper", side_effect=lambda name:linux if name=="bundle_python_runtime" else verifier), \
                 patch.object(m, "loads", side_effect=lambda path:[str(prefix / "Python")] if path==daemon else []), \
                 patch.object(m.subprocess, "check_output", side_effect=lambda args, **kw:"46.0.4" if args[0]=="python" else str(prefix / "Python")), \
                 patch.object(m.subprocess, "run", side_effect=run) as calls:
                included = m.bundle_macos_python(root, source_root=base / "source", python="python")
            staged = destination / "lib/python3.12/site-packages" / cffi.name
            self.assertEqual(staged.read_bytes(), cffi.read_bytes())
            self.assertIn(str(staged.relative_to(root)), included)
            self.assertTrue(any(call.args[0][:4]==["codesign","--force","--sign","-"]
                                and call.args[0][-1]==str(staged) for call in calls.call_args_list))

if __name__ == '__main__':unittest.main()
