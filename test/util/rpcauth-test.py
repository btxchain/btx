#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test share/rpcauth/rpcauth.py
"""
import configparser
import hmac
import importlib
import json
import os
import re
import subprocess
import sys
import unittest

class TestRPCAuth(unittest.TestCase):
    def setUp(self):
        config = configparser.ConfigParser()
        config_path = os.path.abspath(
            os.path.join(os.sep, os.path.abspath(os.path.dirname(__file__)),
            "../config.ini"))
        with open(config_path, encoding="utf8") as config_file:
            config.read_file(config_file)
        self.rpcauth_path = config['environment']['RPCAUTH']
        sys.path.insert(0, os.path.dirname(self.rpcauth_path))
        self.rpcauth = importlib.import_module('rpcauth')

    def test_generate_salt(self):
        for i in range(16, 32 + 1):
            self.assertEqual(len(self.rpcauth.generate_salt(i)), i * 2)

    def test_generate_password(self):
        """Test that generated passwords only consist of urlsafe characters."""
        r = re.compile(r"[0-9a-zA-Z_-]*")
        generated_secret = self.rpcauth.generate_password()
        self.assertTrue(r.fullmatch(generated_secret))

    def test_check_password_hmac(self):
        salt = self.rpcauth.generate_salt(16)
        auth_secret = self.rpcauth.generate_password()
        computed_hmac = self.rpcauth.password_to_hmac(salt, auth_secret)

        m = hmac.new(salt.encode('utf-8'), auth_secret.encode('utf-8'), 'SHA256')
        expected_hmac = m.hexdigest()

        self.assertEqual(expected_hmac, computed_hmac)

    def test_json_output_preserves_password_key(self):
        result = subprocess.run(
            [sys.executable, self.rpcauth_path, 'user', '-j'],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(result.stdout)
        self.assertIn('password', payload)
        self.assertIn('credential', payload)
        self.assertEqual(payload['password'], payload['credential'])
        self.assertEqual(payload['username'], 'user')
        self.assertIn('rpcauth', payload)

if __name__ == '__main__':
    unittest.main()
