#!/usr/bin/env python3
"""Predicate checks for the disposable regtest qualification gate."""
from qualify_regtest import spend_allowed

assert spend_allowed(101) is True
assert spend_allowed(99) is False
assert spend_allowed(100) is False
assert spend_allowed(None) is False
assert spend_allowed('101') is False
print('pass')
