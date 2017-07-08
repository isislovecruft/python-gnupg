#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This file is part of python-gnupg, a Python interface to GnuPG.
# Copyright © 2013 Isis Lovecruft, <isis@leap.se> 0xA3ADB67A2CDB8B35
#           © 2013 Andrej B.
#           © 2013 LEAP Encryption Access Project
#           © 2008-2012 Vinay Sajip
#           © 2005 Steve Traugott
#           © 2004 A.M. Kuchling
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the included LICENSE file for details.

"""test_util.py
----------------
A test harness and unittests for _util.py.
"""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import with_statement

import unittest
from gpg._parsers import UsageError

## see PEP-366 http://www.python.org/dev/peps/pep-0366/

print("NAME: %r" % __name__)
print("PACKAGE: %r" % __package__)
try:
    import gpg._parsers as parsers
except (ImportError, ValueError) as ierr:
    raise SystemExit(str(ierr))


class TestKeyExpiryExtensionParser(unittest.TestCase):
    """:class:`unittest.TestCase <TestCase>`s for python-gnupg util."""

    def test_happy_path(self):
        try:
            parsers.KeyExtensionInterface("0")
            parsers.KeyExtensionInterface("113")
            parsers.KeyExtensionInterface("2w")
            parsers.KeyExtensionInterface("3m")
            parsers.KeyExtensionInterface("54y")
        except UsageError:
            self.fail('more than one digit, key extension option, raises exceptions')

    def test_anything_that_is_not_w_y_m_is_not_allowed(self):
        with self.assertRaises(UsageError):
            parsers.KeyExtensionInterface("2x")

    def test_negative_number_is_not_allowed(self):
        with self.assertRaises(UsageError):
            parsers.KeyExtensionInterface("-1")

    def test_letters_without_a_number_is_not_allowed(self):
        with self.assertRaises(UsageError):
            parsers.KeyExtensionInterface("w")

    def test_letters_before_a_number_is_not_allowed(self):
        with self.assertRaises(UsageError):
            parsers.KeyExtensionInterface("w3")

    def test_more_than_w_is_not_allowed_option(self):
        with self.assertRaises(UsageError):
            parsers.KeyExtensionInterface("2ww")

    def test_more_than_m_is_not_allowed_option(self):
        with self.assertRaises(UsageError):
            parsers.KeyExtensionInterface("7mm")

    def test_more_than_y_is_not_allowed_option(self):
        with self.assertRaises(UsageError):
            parsers.KeyExtensionInterface("9yy")
