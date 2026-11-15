#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile,unittest,struct,zipfile,types
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('winbundle',ROOT/'scripts/release/bundle_windows_python_runtime.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class RuntimeTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.release=self.root/'release';(self.release/'bin').mkdir(parents=True);self.source=self.root/'runtime';self.source.mkdir();self.pe=bytearray(70);self.pe[:2]=b'MZ';struct.pack_into('<I',self.pe,60,64);self.pe[64:68]=b'PE\0\0';struct.pack_into('<H',self.pe,68,0x8664)
  for n in ('python312.dll','python3.dll'):(self.source/n).write_bytes(self.pe)
  (self.release/'bin/btxd.exe').write_bytes(self.pe);(self.source/'LICENSE.txt').write_text('licence')
  with zipfile.ZipFile(self.source/'python312.zip','w') as z:z.writestr('encodings/__init__.pyc',b'x');z.writestr('os.pyc',b'x')
  site=self.source/'Lib/site-packages';(site/'cryptography').mkdir(parents=True);(site/'cryptography/__init__.py').write_text('');(site/'cryptography-46.0.4.dist-info').mkdir();(site/'cryptography-46.0.4.dist-info/METADATA').write_text('Version: 46.0.4\n');(site/'_cffi_backend.pyd').write_bytes(self.pe);(site/'cryptography/hazmat/bindings').mkdir(parents=True);(site/'cryptography/hazmat/bindings/_rust.pyd').write_bytes(self.pe)
  self.verify=types.SimpleNamespace(classify=lambda p:'pe',pe_imports=lambda p:['python312.dll'] if p.name=='btxd.exe' else ['python3.dll'] if p.name=='_rust.pyd' else ['python312.dll'] if p.name=='python3.dll' else [],WINDOWS_SYSTEM_DLLS=set(),pe_problems=lambda *a:[])
  self.mock=patch.object(m,'verifier',return_value=self.verify);self.mock.start();self.addCleanup(self.mock.stop)
 def test_required_runtime(self):
  with self.assertRaisesRegex(RuntimeError,'requires'):m.bundle_windows_python(self.release,None)
 def test_layout_and_transitive_adjacent_alias(self):
  m.bundle_windows_python(self.release,self.source);out=self.release/'bin';nested=out/'Lib/site-packages/cryptography/hazmat/bindings'
  self.assertEqual((nested/'python312.dll').read_bytes(),bytes(self.pe));self.assertEqual((out/'python312._pth').read_text(),'python312.zip\n.\nLib/site-packages\n');self.assertTrue((out/'Lib/site-packages/cryptography-46.0.4.dist-info/METADATA').exists())
 def test_conflicting_nested_python_refused(self):
  (self.source/'Lib/site-packages/cryptography/hazmat/bindings/python312.dll').write_bytes(bytes(self.pe)+b'different')
  with self.assertRaisesRegex(RuntimeError,'Conflicting runtime dependency'):m.bundle_windows_python(self.release,self.source)
 def test_wrong_arch(self):
  struct.pack_into('<H',self.pe,68,0xaa64);(self.source/'python312.dll').write_bytes(self.pe)
  with self.assertRaisesRegex(RuntimeError,'x64'):m.bundle_windows_python(self.release,self.source)
 def test_native_crypto_missing(self):
  (self.source/'Lib/site-packages/cryptography/hazmat/bindings/_rust.pyd').unlink()
  with self.assertRaisesRegex(RuntimeError,'Native cryptography'):m.bundle_windows_python(self.release,self.source)
 def test_crypto_missing(self):
  (self.source/'Lib/site-packages/cryptography/__init__.py').unlink()
  with self.assertRaisesRegex(RuntimeError,'cryptography'):m.bundle_windows_python(self.release,self.source)
 def test_unknown_dependency(self):
  self.verify.pe_imports=lambda p:['python312.dll'] if p.name=='btxd.exe' else ['foreign.dll']
  with self.assertRaisesRegex(RuntimeError,'dependency'):m.bundle_windows_python(self.release,self.source)
class SystemDependencyTest(unittest.TestCase):
 def test_windows_crypto_system_dependency_and_unknown_refusal(self):
  v=m.verifier()
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);image=root/'native.pyd';image.write_bytes(b'fixture')
   with patch.object(v,'pe_imports',return_value=['bcryptprimitives.dll','propsys.dll','cabinet.dll','msi.dll']):self.assertEqual(v.pe_problems(root,[image]),[])
   with patch.object(v,'pe_imports',return_value=['unknown-runtime.dll']):self.assertTrue(v.pe_problems(root,[image]))
   with patch.object(v,'pe_imports',return_value=['libomp140.x86_64.dll']):self.assertTrue(v.pe_problems(root,[image]))

class OpenMPRuntimeTest(unittest.TestCase):
 def setUp(self):
  RuntimeTest.setUp(self)
  self.verify.pe_imports=lambda p:['libomp140.x86_64.dll'] if p.name=='btxd.exe' else []
  self.omp=self.root/'omp';self.omp.mkdir();(self.omp/'libomp.dll').write_bytes(self.pe);(self.omp/'LICENSE.txt').write_text('LLVM license')
 def test_openmp_explicit_required(self):
  with self.assertRaisesRegex(RuntimeError,'requires'):m.bundle_windows_openmp(self.release,None)
 def test_openmp_single_alias_and_licence(self):
  m.bundle_windows_openmp(self.release,self.omp)
  self.assertEqual((self.release/'bin/libomp140.x86_64.dll').read_bytes(),bytes(self.pe));self.assertFalse((self.release/'bin/libomp.dll').exists());self.assertTrue((self.release/'share/licenses/llvm-openmp/LICENSE.txt').is_file())
 def test_openmp_unknown_dependency_refused(self):
  self.verify.pe_problems=lambda *args:['unknown.dll']
  with self.assertRaisesRegex(RuntimeError,'unknown.dll'):m.bundle_windows_openmp(self.release,self.omp)
 def test_openmp_extra_runtime_refused(self):
  (self.release/'bin/libomp.dll').write_bytes(self.pe)
  with self.assertRaisesRegex(RuntimeError,'Multiple OpenMP'):m.bundle_windows_openmp(self.release,self.omp)
 def test_openmp_mixed_names_refused(self):
  self.verify.pe_imports=lambda p:['libomp.dll','libomp140.x86_64.dll']
  with self.assertRaisesRegex(RuntimeError,'mixed'):m.bundle_windows_openmp(self.release,self.omp)
 # RuntimeTest's Python cases require the Python-specific mock instead.


if __name__=='__main__':unittest.main()
