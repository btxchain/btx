#!/usr/bin/env python3
"""Tool-mapping tests, not native runtime evidence."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
PATH = ROOT / "contrib/model-security/guard_client.py"
SPEC = importlib.util.spec_from_file_location("guard_client", PATH)
CLIENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLIENT)


class AdapterTests(unittest.TestCase):
    def test_read(self):
        self.assertEqual(CLIENT.translate_tool("read_file", '{"path":"a.txt"}'), {"tool":"read","path":"a.txt"})
    def test_shell_denied(self):
        with self.assertRaises(CLIENT.GuardError): CLIENT.translate_tool("exec_command", '{"command":"not executed"}')
    def test_network_denied(self):
        with self.assertRaises(CLIENT.GuardError): CLIENT.translate_tool("http_request", '{"url":"example.invalid"}')
    def test_duplicates(self):
        with self.assertRaises(CLIENT.GuardError): CLIENT.translate_tool("read_file", '{"path":"a","path":"b"}')
    def test_extra_authority(self):
        with self.assertRaises(CLIENT.GuardError): CLIENT.translate_tool("read_file", '{"path":"a","grant":"own"}')
    def test_oversized_payload(self):
        with self.assertRaises(CLIENT.GuardError): CLIENT.translate_tool("write_new_file", '{"path":"a","payload_hex":"'+('00'*65537)+'"}')
    def test_invalid_hex(self):
        with self.assertRaises(CLIENT.GuardError): CLIENT.translate_tool("write_new_file", '{"path":"a","payload_hex":"GG"}')
    def test_static_requires_package_hash(self):
        with self.assertRaises(CLIENT.GuardError): CLIENT.translate_tool("run_approved_static", '{"package":"untrusted-name","payload_hex":""}')


if __name__ == '__main__': unittest.main(verbosity=2)
