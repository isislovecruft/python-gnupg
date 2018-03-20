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

"""test_gnupg.py
----------------
A test harness and unittests for gnupg.py.
"""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import with_statement

import datetime
from argparse   import ArgumentParser
from codecs     import open as open
from functools  import wraps
from glob       import glob
from time       import localtime
from time       import mktime

import doctest
import io
import os
import shutil
import sys
import tempfile

## This is less applicable now that we're using distribute with a bootstrap
## script for newer versions of distribute, and pip>=1.3.1, since both of
## these dependencies require Python>=2.6 in order to have proper SSL support.
##
## Use unittest2 if we're on Python2.6 or less:
if sys.version_info[0] == 2 and sys.version_info[1] <= 6:
    import unittest2 as unittest
else:
    import unittest

from mock import patch, MagicMock
import gnupg

## see PEP-366 http://www.python.org/dev/peps/pep-0366/
print("NAME: %r" % __name__)
print("PACKAGE: %r" % __package__)
try:
    import gnupg._util    as _util
    import gnupg._parsers as _parsers
    import gnupg._logger  as _logger
except (ImportError, ValueError) as ierr:
    raise SystemExit(str(ierr))


log = _util.log
log.setLevel(9)

print("Current source directory: %s" % _util._here)
print("Current os.cwd directory: %s" % os.getcwd())
_tests = os.path.join(_util._here, 'test')
_files = os.path.join(_tests, 'files')
_tempd = os.path.join(_tests, 'tmp')

tempfile.tempdir = _tempd
if not os.path.isdir(tempfile.gettempdir()):
    log.debug("Creating temporary testing directory: %s"
              % tempfile.gettempdir())
    os.makedirs(tempfile.gettempdir())

@wraps(tempfile.TemporaryFile)
def _make_tempfile(*args, **kwargs):
    return tempfile.TemporaryFile(dir=tempfile.gettempdir(),
                                  *args, **kwargs)

RETAIN_TEST_DIRS = True

KEYS_TO_IMPORT = """-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=sqld
-----END PGP PUBLIC KEY BLOCK-----"""


PUBKEY_ID_FRED_FOO = "E950D5D4BC6CA86E"
PUBKEY_FRED_FOO = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFdVYo8BCAC6NygwXJhmlwa87uAEfypH5dz0ANuMhHn7Cjf7Xgc/d8dwOnCe
ai0cpEsdnraankzG9kxqxqWZgx/oIO1iH3Qcd+BfkZG8VFew7mJqFgnFaKWUCUXb
p6JLiwOIVUXhJScUr7OT7yg45of53ECoXFSrmLoWbhSd1+eetCzwIBTRgoRAGsv1
ifA9+RtfeR8N2/VaIMOz9cmkvBjvbSSubPQVjbRQbxHaFhC+v1MJMcra9eXcdQ0h
gopOENagfW4zDOJGAsLZ7KVCEGPSncALLj8/fF79HwzuMf6zUfsfkxkmQv7bpW6g
Nab2ES39GVQFMKSPww3jv6bHZpjw7ibQrT9/ABEBAAG0F0ZyZWQgRm9vIDxmcmVk
QGZvby5jb20+iQE5BBMBCAAjBQJXVWKPAhsDBwsJCAcDAgEGFQgCCQoLBBYCAwEC
HgECF4AACgkQ6VDV1LxsqG6xsAf6AjMvCU/+PFsqMppeF706Ax3TSOcwx+611uCA
tAa+nT0xZm1m66txe6YgRPcmF8uHM6IXDyb3GQAtrsjFt0WRb+xTpM+sOEmRoh6S
jUnIotwhSlAkicGe+yqXqDTRGk+06AiCNV5ujB5V3rDZj2zraNkwG0dc3hox+rNn
pw7Cy0GlnXki3Ka9dpFiUOePg/aZXXSYbW/qP9CBH89dzS3xga8iv8pvjhhE76zc
/kCGI6W6OpWQhG/HkdolDuXDiRV5n7FKOe8Kck8O7mdRWEBam1pG2e3M+J0L6e46
b/g5ksvKjeUcLl+1H6x3U3Pv7+ZTYun/rn//+fyHzzFu8VfCuokBHAQTAQgABgUC
V1Vi4wAKCRDtgpuHsUs7IWskCADTk7LwSRAr98BtUUwqOzsAw630sO/P08JuAwPQ
C2q170i60BeXHAACgmpE+ZAZ7y7UdZSMVLq5pom2zf4bb+pcBZGFkgFV9q5iCXKC
Nx/vr6TdDquH6U7kjyG4qHWRgWN+zRHdDTeRe6W7IzlH5HPNCBIKBOv+Gh9BOf4h
HzMJflSTbYemXxHtULf4rer2XeOq+VbJX8544gkbtBL5VWLTQKdbFGIyEuziBXjg
kP06OKmH6oJ9eFfB5Hbcu3GZWeoLVO0CkhhQ65KJWzKFyy8gIUG3+vKIcLfBhAaJ
pIfoizFn8D2NQ3l+sWkxxgtVbk/6CL/nXheUp8Ph4XrBx9COuQENBFdVYo8BCAC0
vv5CxxhLZIsDVWfO379rgtZStq/2ul6QlfEwdT8hZmGaQXCN2g19nhVJ7kuq5yO2
cAfB7y8YgQAlgCCgFHNPkwvJRh7Z2rcD80TmbdXit8+Am0a4Wrml2cA49tynrXx/
4JzDib92t+2BG+bBqJnIZOYhEHaXYgVaNI0CvTpolA9CDIr7bc1dToIU2J9go3dQ
Bci9as9K6x3DKybBzoY/PMaUXlru9RNdcz9eA1/082tWZOyLxPZePBuQOe4F8GkW
tnxaelfptRPwWhThUTQ4kbcxL5tOG7BYemeulIccO1MU6pqS2RpNs7WdfMx7RoEN
E6AQzuGwiYo5O/L7vTo9ABEBAAGJAR8EGAEIAAkFAldVYo8CGwwACgkQ6VDV1Lxs
qG6XlggAidejM3WT6wP3+mkb4Ki6dmrRRgETZAQH76pT3epYVfPrUxeRurdCuPv4
6DSl3VAPu/ekAWkV5Fzvxu936jxhYWiB1F4fQno7Rxsfh00qBqSYZKO9+BEWx1lj
IC5f+ch1UDqAfjwlOGAP2a/YtT3wSwxUTKkZSjFsp4r/4cRxMY6k9xi6lPDSnrux
k6qvsgfFVYhc0Hot3nuDBkth2tp0zodRuhmBG0jaIkbsWQDTxqQiHcbcAqdqgsGK
4pUqsH73PlyfpbS0d8syQf9Uzl4VvX2zTdgIvEGkZi3BwtM2tPXbl+/H9yBs5Jo0
oDzauPrPFwyRVgWpEuKp9pZbtF045Q==
=9e5u
-----END PGP PUBLIC KEY BLOCK-----
"""

PUBKEY_ID_BOB_BAR = "ED829B87B14B3B21"
PUBKEY_BOB_BAR = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFdVYskBCAD3CgbmVDqd9rINYBHO9C3WVSOIZ0k0OM4hMAHGMD2R+WDTNKKm
09yzwpaL00tzrX2PVZMu8/zpyoyRTluNPfdVLDFF4nrq4AgDze/d8Pc2fwFZVZMQ
L2ZPQ4O++cC1oLuiYRLILL66tBFAuIMPGdTAG6Izj5PQaytAE/1C40dvEESi31sk
mgyAUcw2U8Zf9Jjd8yJLBsFNbIiiw4J0qH/zcCKiL63J+Q18Dd2M6HBFaX45aJPQ
cIehCIuergLWJBXRDIIKiktyAONdSWCm5ujfDQT9M9hSV2BHki9+0e+zff8yCGgT
pIEPf7Sb8JgnR16puEBj0YS0w8Gpa0mo1oP/ABEBAAG0FEJvYiBCYXIgPGJvYkBi
YXIuaW8+iQE5BBMBCAAjBQJXVWLJAhsDBwsJCAcDAgEGFQgCCQoLBBYCAwECHgEC
F4AACgkQ7YKbh7FLOyGVBAgAjTX8cNcp+VpJFzDUL6uIYrDhaRwcjdTnWatbG10Q
2pPRhDd7Yf1ZubkqEALUNsQnSyVuXsab4F1FuvE9O9Cfe0t4v0eNkEHDx2/IYwiZ
1fgHfXhIqOoMdiCn6a51t7hRmkBSebi6uUEKkRscBTg/fue2s8q+JqiXWvlNuUPY
LeCNmebnMryjjJylq5+/QY4A6sJGh9JxDPCkT2aS9AC9vrPXAlrgoVoQh6SX2xwP
uC/Aksl5fv/dD8LMLBukkiwhYZr6sTIXFhmtw24D/WLz8tQQIySnokzFILcr3V/8
J7GLFa4YXAH8rGq0K+ero3rHTEeQh9jOp5gAvQHarjjJUbkBDQRXVWLJAQgAzd8t
5uns5xYjYSVjERlH//L4lPNOhmy9grhhQXd8A6/GQeNncB7Or28R4/cXVLgnL2mD
xBbhiV5HQz6nERY0GxSkgWwZ7LJhtgqilv+MEQGbEogsicS2D4CC7A3lUuBcRXF/
AdawIFkmORu7B2ICJDzw1rUEtcPdAY3uU8G/ja7zY8mEgwIdEP48eqkUi15aASCu
UowoMN5aYaCILHRXOOgPkYYd4LcQBV2Y6xSLTgkL7Sl878J5a+y6QNSOkm85IhEL
QC5PqMxZcrSjTnVlFWRnIHUJ0IDgsUPRyp6+1VZ72yXTi8BhlOSKE74SOLvUeQMJ
C4mISmcm+QXCpKy7dwARAQABiQEfBBgBCAAJBQJXVWLJAhsMAAoJEO2Cm4exSzsh
kawH/3RywwJ1oIjg5y9U/2V1SaNVdh+Kk/x2xs9HzbpUuo1MA5S04MZ+MOl05JOu
gF98ye6z3qkjazkTC+0CdteH1+pi1WEwxkxQUiswGaVPPscr+6f9L/rS/IuGbxf8
qe26J6pD+EjMaS7uCrOgQCIUH1V8TzlWMyoscH1y5rR/gp1IskIHaYfJ5AIL3eVS
0s7szPFsrUqIt0KI/D0kc9aNapk4qMA0az8gKC+HAGcJfeb6Py2rJfFEpt1rKrbO
NzyH16tLO3htUqPGdfkVx03gsQcSbWDoCQyuiIyzoZ3kX29skSyKO8bFu221WbgN
IW8P249QHz6qLnRMErL80zLU9Go=
=hb7Y
-----END PGP PUBLIC KEY BLOCK-----
"""

def is_list_with_len(o, n):
    return isinstance(o, list) and len(o) == n

def compare_keys(k1, k2):
    """Compare ASCII keys."""
    k1 = k1.split('\n')
    k2 = k2.split('\n')
    return k1 != k2


class GPGTestCase(unittest.TestCase):
    """:class:`unittest.TestCase <TestCase>`s for python-gnupg."""

    def setUp(self):
        """This method is called once per self.test_* method."""
        print("%s%s%s" % (os.linesep, str("=" * 70), os.linesep))
        hd = tempfile.mkdtemp()
        if os.path.exists(hd):
            if not RETAIN_TEST_DIRS:
                self.assertTrue(os.path.isdir(hd), "Not a directory: %s" % hd)
                shutil.rmtree(hd)

        if not os.path.exists(hd):
            os.makedirs(hd)
        self.assertTrue(os.path.isdir(hd), "Not a directory: %s" % hd)

        self.gpg = gnupg.GPG(binary='gpg', homedir=hd)
        self.homedir = hd
        self.keyring = self.gpg.keyring
        self.secring = self.gpg.secring
        self.insecure_prng = False

    def tearDown(self):
        """This is called once per self.test_* method after the test run."""
        if os.path.exists(self.homedir) and os.path.isdir(self.homedir):
            try:
                shutil.rmtree(self.homedir)
            except OSError as ose:
                log.error(ose)
        else:
            log.warn("Can't delete homedir: '%s' not a directory"
                     % self.homedir)

    def test_parsers_fix_unsafe(self):
        """Test that unsafe inputs are quoted out and then ignored."""
        shell_input = "\"&coproc /bin/sh\""
        fixed = _parsers._fix_unsafe(shell_input)
        print(fixed)
        test_file = os.path.join(_files, 'cypherpunk_manifesto')
        self.assertTrue(os.path.isfile(test_file))
        datafd = open(test_file, 'rb')
        has_shell = self.gpg.verify_file(datafd, sig_file=fixed)
        datafd.close()
        self.assertFalse(has_shell.valid)

    def test_parsers_fix_unsafe_semicolon(self):
        """Test that we can't escape into the Python interpreter."""
        shell_input = "; import antigravity ;"
        fixed = _parsers._fix_unsafe(shell_input)

    def test_parsers_is_hex_valid(self):
        """Test that valid hexidecimal passes the parsers._is_hex() check"""
        valid_hex = '0A6A58A14B5946ABDE18E207A3ADB67A2CDB8B35'
        self.assertTrue(_parsers._is_hex(valid_hex))

    def test_parsers_is_hex_lowercase(self):
        """Test parsers._is_hex() with lowercased hexidecimal"""
        valid_hex = 'deadbeef15abad1dea'
        self.assertTrue(_parsers._is_hex(valid_hex))

    def test_parsers_is_hex_invalid(self):
        """Test that invalid hexidecimal fails the parsers._is_hex() check"""
        invalid_hex = 'cipherpunks write code'
        self.assertFalse(_parsers._is_hex(invalid_hex))

    def test_encodings_spiteful(self):
        """Test that a non-existent codec raises a LookupError."""
        enc = '#!@& dealing with unicode in Python2'
        with self.assertRaises(LookupError):
            _util.find_encodings(enc)

    def test_encodings_big5(self):
        """Test that _util.find_encodings works for Chinese Traditional."""
        enc = 'big5'
        coder = _util.find_encodings(enc)
        msg = u'光榮的中國人民應該摧毀中國長城防火牆。'
        encoded = coder.encode(msg)[0]
        decoded = coder.decode(encoded)[0]
        self.assertEqual(msg, decoded)

    def test_encodings_non_specified(self):
        """Test that using the default utf-8 encoding works."""
        coder = _util.find_encodings()
        msg = u'Nutella á brauð mitt, smear það þykkur!'
        encoded = coder.encode(msg)[0]
        decoded = coder.decode(encoded)[0]
        self.assertEqual(msg, decoded)

    def test_homedir_creation(self):
        """Test that a homedir is created if left unspecified"""
        gpg = gnupg.GPG(binary='gpg')
        self.assertTrue(os.path.exists(gpg.homedir),
                        "Not an existing directory: %s" % gpg.homedir)
        self.assertTrue(os.path.isdir(gpg.homedir),
                        "Not a directory: %s" % gpg.homedir)

    def test_binary_discovery(self):
        """Test that the path to gpg is discovered if unspecified"""
        gpg = gnupg.GPG()
        self.assertIsNotNone(gpg.binary)
        self.assertTrue(os.path.exists(gpg.binary),
                        "Path does not exist: %s" % gpg.binary)

    def test_gpg_binary(self):
        """Test that 'gpg --version' does not return an error code."""
        proc = self.gpg._open_subprocess(['--version'])
        result = io.StringIO()
        self.gpg._collect_output(proc, result, stdin=proc.stdin)
        self.assertEqual(proc.returncode, 0)

    def test_gpg_binary_version_str(self):
        """Test that 'gpg --version' returns the expected output."""
        proc = self.gpg._open_subprocess(['--version'])
        result = proc.stdout.read(1024)
        expected1 = b"Supported algorithms:"
        expected2 = b"Pubkey:"
        expected3 = b"Cipher:"
        expected4 = b"Compression:"
        self.assertGreater(result.find(expected1), 0)
        self.assertGreater(result.find(expected2), 0)
        self.assertGreater(result.find(expected3), 0)
        self.assertGreater(result.find(expected4), 0)

    def test_gpg_binary_not_installed(self):
        """Test that Gnupg installation can be detected."""
        env_copy = os.environ
        path_copy = os.environ.pop('PATH')
        with self.assertRaises(RuntimeError):
            gnupg.GPG(homedir=self.homedir)
        os.environ = env_copy
        os.environ.update({'PATH': path_copy})

    def test_gpg_binary_not_abs(self):
        """Test that a non-absolute path to gpg results in a full path."""
        print(self.gpg.binary)
        self.assertTrue(os.path.isabs(self.gpg.binary))

    @patch('gnupg._util._version_from_list_config', return_value='1.2.3')
    def test_make_args_drop_protected_options_gpg_v1(self, td):
        """Test that unsupported gpg options are dropped, and supported ones remain."""
        self.setUp()
        self.gpg.options = ['--tyrannosaurus-rex', '--stegosaurus', '--lock-never', '--trust-model always']
        gpg_binary_path = _util._find_binary('gpg')
        cmd = self.gpg._make_args(None, False)
        expected = [gpg_binary_path,
                    '--no-options --no-emit-version --no-tty --status-fd 2',
                    '--homedir "%s"' % self.homedir,
                    '--no-default-keyring --keyring %s' % self.keyring,
                    '--secret-keyring %s' % self.secring,
                    '--no-use-agent',
                    '--lock-never',
                    '--trust-model always']
        self.assertListEqual(cmd, expected)

    @patch('gnupg._util._version_from_list_config', return_value='2.3.4')
    def test_make_args_drop_protected_options_gpg_v2(self, td):
        """Test that unsupported gpg options are dropped, and supported ones remain."""
        self.setUp()
        self.gpg.options = ['--tyrannosaurus-rex', '--stegosaurus', '--lock-never', '--trust-model always']
        gpg_binary_path = _util._find_binary('gpg')
        cmd = self.gpg._make_args(None, False)
        expected = [gpg_binary_path,
                    '--no-options --no-emit-version --no-tty --status-fd 2',
                    '--homedir "%s"' % self.homedir,
                    '--no-default-keyring --keyring %s' % self.keyring,
                    '--secret-keyring %s' % self.secring,
                    '--lock-never',
                    '--trust-model always']
        self.assertListEqual(cmd, expected)

    def test_make_args(self):
        """Test argument line construction."""
        not_allowed = ['--bicycle', '--zeppelin', 'train', 'flying-carpet']
        self.gpg.options = not_allowed[:-2]
        args = self.gpg._make_args(not_allowed[2:], False)
        self.assertTrue(len(args) == 6)
        for na in not_allowed:
            self.assertNotIn(na, args)

    def test_list_keys_initial_public(self):
        """Test that initially there are no public keys."""
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 0),
                        "Empty list expected...got instead: %s"
                        % str(public_keys))

    def test_list_keys_initial_secret(self):
        """Test that initially there are no secret keys."""
        private_keys = self.gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 0),
                        "Empty list expected...got instead: %s"
                        % str(private_keys))

    def test_copy_data_bytesio(self):
        """Test that _copy_data() is able to duplicate byte streams."""
        message = b"This is a BytesIO string."
        instream = io.BytesIO(message)
        self.assertEqual(message, instream.getvalue())

        out_filename = 'test-copy-data-bytesio'

        # Create the test file:
        try:
            cwd = os.getcwdu()
        except AttributeError:
            cwd = os.getcwd() # not present in Python 3
        outfile = os.path.join(cwd, out_filename)
        outstream = open(outfile, 'wb+')

        # _copy_data() will close both file descriptors
        _util._copy_data(instream, outstream)

        self.assertTrue(outstream.closed)
        self.assertFalse(instream.closed)
        self.assertTrue(os.path.isfile(outfile))

        with open(outfile) as out:
            out.flush()
            out.seek(0)
            output = out.read()
            self.assertEqual(message, output)

        os.remove(outfile)

    def generate_key_input(self, real_name, email_domain, key_length=None,
                           expire_date=1,
                           key_type=None, subkey_type=None, passphrase=None):
        """Generate a GnuPG batch file for key unattended key creation."""
        name = real_name.lower().replace(' ', '')

        key_type   = 'RSA'if key_type is None else key_type
        key_length = 1024 if key_length is None else key_length

        batch = {'Key-Type': key_type,
                 'Key-Length': key_length,
                 'Expire-Date': expire_date,
                 'Name-Real': '%s' % real_name,
                 'Name-Email': ("%s@%s" % (name, email_domain))}

        batch['Passphrase'] = name if passphrase is None else passphrase

        if subkey_type is not None:
            batch['Subkey-Type'] = subkey_type
            batch['Subkey-Length'] = key_length

        key_input = self.gpg.gen_key_input(testing=self.insecure_prng, **batch)
        return key_input

    def generate_key(self, real_name, email_domain, **kwargs):
        """Generate a basic key."""
        key_input = self.generate_key_input(real_name, email_domain, **kwargs)
        key = self.gpg.gen_key(key_input)
        print("\nKEY TYPE: ", key.type)
        print("KEY FINGERPRINT: ", key.fingerprint)
        return key

    def test_gen_key_input(self):
        """Test that GnuPG batch file creation is successful."""
        key_input = self.generate_key_input("Francisco Ferrer", "an.ok")
        if _util._py3k:
            self.assertIsInstance(key_input, str)
        else:
            self.assertIsInstance(key_input, basestring)
        self.assertGreater(key_input.find('Francisco Ferrer'), 0)

    def test_rsa_key_generation(self):
        """Test that RSA key generation succeeds."""
        key = self.generate_key("Ralph Merkle", "xerox.com")
        self.assertIsNotNone(key.type)
        self.assertIsNotNone(key.fingerprint)

    def test_rsa_key_generation_with_unicode(self):
        """Test that RSA key generation succeeds with unicode characters."""
        key = self.generate_key("Anaïs de Flavigny", "êtrerien.fr")
        self.assertIsNotNone(key.type)
        self.assertIsNotNone(key.fingerprint)

    def test_rsa_key_generation_with_subkey(self):
        """Test that RSA key generation succeeds with additional subkey."""
        key = self.generate_key("John Gilmore", "isapu.nk",
                                subkey_type='RSA')
        self.assertIsNotNone(key.type)
        self.assertIsNotNone(key.fingerprint)

    def test_dsa_key_generation(self):
        """Test that DSA key generation succeeds."""
        key = self.generate_key("Ross Anderson", "bearli.on")
        self.assertIsNotNone(key.type)
        self.assertIsNotNone(key.fingerprint)

    def test_dsa_key_generation_with_unicode(self):
        """Test that DSA key generation succeeds with unicode characters."""
        key = self.generate_key("破壊合計する", "破壊合計する.日本")
        self.assertIsNotNone(key.type)
        self.assertIsNotNone(key.fingerprint)

    def test_dsa_key_generation_with_subkey(self):
        """Test that RSA key generation succeeds with additional subkey."""
        key = self.generate_key("Eli Biham", "bearli.on",
                                subkey_type='ELG-E')
        self.assertIsNotNone(key.type)
        self.assertIsNotNone(key.fingerprint)

    def test_key_generation_with_invalid_key_type(self):
        """Test that key generation handles invalid key type."""
        params = {
            'Key-Type': 'INVALID',
            'Key-Length': 1024,
            'Subkey-Type': 'ELG-E',
            'Subkey-Length': 1024,
            'Name-Comment': 'A test user',
            'Expire-Date': 1,
            'Name-Real': 'Test Name',
            'Name-Email': 'test.name@example.com',
        }
        batch = self.gpg.gen_key_input(**params)
        key = self.gpg.gen_key(batch)
        self.assertIsNone(key.type)
        self.assertIsNone(key.fingerprint)

    def test_key_generation_with_colons(self):
        """Test that key generation handles colons in Name fields."""
        params = {
            'key_type': 'RSA',
            'name_real': 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19',
            'name_comment': 'dummy comment',
            'name_email': 'test.name@example.com',
        }
        batch = self.gpg.gen_key_input(**params)
        key = self.gpg.gen_key(batch)
        self.assertIsNotNone(key.type)
        self.assertIsNotNone(key.fingerprint)

    def test_key_generation_import_list_with_colons(self):
        """Test that key generation handles colons in Name fields."""
        params = {
            'key_type': 'RSA',
            'name_real': 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19',
            'name_comment': 'dummy comment',
            'name_email': 'test.name@example.com',
        }
        batch = self.gpg.gen_key_input(**params)
        self.assertIsInstance(batch, str)
        key = self.gpg.gen_key(batch)
        keys = self.gpg.list_keys()
        self.assertIsNotNone(key)
        self.assertEqual(len(keys), 1)
        key = keys[0]
        self.assertIsNotNone(key['type'])
        self.assertIsNotNone(key['fingerprint'])
        uids = key['uids']
        self.assertEqual(len(uids), 1)
        uid = uids[0]
        self.assertEqual(uid, 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19 '
                              '(dummy comment) <test.name@example.com>')

    def test_key_generation_with_empty_value(self):
        """Test that key generation handles empty values."""
        params = {'name_real': ' '}
        batch = self.gpg.gen_key_input(**params)
        self.assertTrue('\nName-Real: Autogenerated Key\n' in batch)

    def test_key_generation_override_default_value(self):
        """Test that overriding a default value in gen_key_input() works."""
        params = {'name_comment': 'A'}
        batch = self.gpg.gen_key_input(**params)
        self.assertFalse('\nName-Comment: Generated by python-gnupg\n' in batch)
        self.assertTrue('\nName-Comment: A\n' in batch)

    def test_list_keys_after_generation(self):
        """Test that after key generation, the generated key is available."""
        self.test_list_keys_initial_public()
        self.test_list_keys_initial_secret()
        self.generate_key("Johannes Trithemius", 'iusedcarrierpidgeons@inste.ad')
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 1),
                        "1-element list expected")
        private_keys = self.gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 1),
                        "1-element list expected")

    def test_list_revoked_key(self):
        """Test that a revoke key is set."""
        self.assertEqual(len(self.gpg.list_keys()), 0)
        with open(os.path.join(_files, 'revoked_key.pub')) as revoked_key:
            self.gpg.import_keys(revoked_key.read())
        result = self.gpg.list_sigs("1763FE94FC05F492285C2B7BA658D626E2A17629")
        self.assertEqual(len(self.gpg.list_keys()), 1)
        self.assertEqual(result[0]['rev']['keyid'], 'A658D626E2A17629')

    def test_revoke_and_not_revoked_key(self):
        """Test that a revoke key is set, but a nun revoked key still valid"""
        with open(os.path.join(_files, 'revoked_key.pub')) as revoked_key:
            self.gpg.import_keys(revoked_key.read())

        self.gpg.list_sigs("1763FE94FC05F492285C2B7BA658D626E2A17629")

        with open(os.path.join(_files, 'test_key_1.sec')) as fh1:
            res = self.gpg.import_keys(fh1.read())

        result = self.gpg.list_sigs(res.fingerprints[0])
        self.assertEqual(len(self.gpg.list_keys()), 2)
        self.assertEqual(result[1]['rev'], {})

    def test_public_keyring(self):
        """Test that the public keyring is found in the gpg home directory."""
        ## we have to use the keyring for GnuPG to create it:
        keys = self.gpg.list_keys()
        self.assertTrue(os.path.isfile(self.gpg.keyring))

    def test_secret_keyring(self):
        """Test that the secret keyring is found in the gpg home directory."""
        ## we have to use the secring for GnuPG to create it:
        keys = self.gpg.list_keys(secret=True)
        self.assertTrue(os.path.isfile(self.gpg.secring))

    def test_recv_keys_default(self):
        """Testing receiving keys from a keyserver."""
        fpr = '0A6A58A14B5946ABDE18E207A3ADB67A2CDB8B35'
        key = self.gpg.recv_keys(fpr)
        self.assertIsNotNone(key)
        self.assertNotEquals(key, "")
        self.assertGreater(len(str(key)), 0)
        keyfile = os.path.join(_files, 'test_key_3.pub')
        log.debug("Storing downloaded key as %s" % keyfile)
        with open(keyfile, 'w') as fh:
            fh.write(str(key))
        self.assertTrue(os.path.isfile(keyfile))
        self.assertGreater(os.stat(keyfile).st_size, 0)

    def test_import_and_export(self):
        """Test that key import and export works."""
        self.test_list_keys_initial_public()
        gpg = self.gpg
        result = gpg.import_keys(KEYS_TO_IMPORT)
        self.assertEqual(result.summary(), '2 imported')
        public_keys = gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 2),
                        "2-element list expected")
        private_keys = gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 0),
                        "Empty list expected")
        ascii = gpg.export_keys([k['keyid'] for k in public_keys])
        self.assertTrue(ascii.find("PGP PUBLIC KEY BLOCK") >= 0,
                        "Exported key should be public")
        ascii = ascii.replace("\r", "").strip()
        match = compare_keys(ascii, KEYS_TO_IMPORT)
        if match:
            log.info("was: %r", KEYS_TO_IMPORT)
            log.info("now: %r", ascii)
        self.assertEqual(0, match, "Keys must match")

        #Generate a key so we can test exporting private keys
        key = self.generate_key('Shai Halevi', 'xorr.ox')
        ascii = gpg.export_keys(key.fingerprint, True)
        self.assertTrue(ascii.find("PGP PRIVATE KEY BLOCK") >= 0,
                        "Exported key should be private")

    def test_import_only(self):
        """Test that key import works."""
        self.test_list_keys_initial_public()
        self.assertTrue(self.gpg.import_keys(KEYS_TO_IMPORT))
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 2),
                        "2-element list expected")
        private_keys = self.gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 0),
                        "Empty list expected")
        ascii = self.gpg.export_keys([k['keyid'] for k in public_keys])
        self.assertTrue(ascii.find("PGP PUBLIC KEY BLOCK") >= 0,
                        "Exported key should be public")
        ascii = ascii.replace("\r", "").strip()
        match = compare_keys(ascii, KEYS_TO_IMPORT)
        if match:
            log.info("was: %r", KEYS_TO_IMPORT)
            log.info("now: %r", ascii)
        self.assertEqual(0, match, "Keys must match")

    def test_signature_string_algorithm_encoding(self):
        """Test that signing a message string works."""
        key = self.generate_key("Werner Koch", "gnupg.org")
        message = "Damn, I really wish GnuPG had ECC support."
        sig = self.gpg.sign(message, default_key=key.fingerprint,
                            passphrase='wernerkoch')
        print("SIGNATURE:\n", sig.data)
        self.assertIsNotNone(sig.data)
        print("ALGORITHM:\n", sig.sig_algo)
        self.assertIsNotNone(sig.sig_algo)

        log.info("Testing signature strings with alternate encodings.")
        self.gpg._encoding = 'latin-1'
        message = "Mêle-toi de tes oignons"
        sig = self.gpg.sign(message, default_key=key.fingerprint,
                            passphrase='wernerkoch')
        self.assertTrue(sig)
        print("SIGNATURE:\n", sig.data)
        self.assertIsNotNone(sig.data)
        print("ALGORITHM:\n", sig.sig_algo)
        self.assertIsNotNone(sig.sig_algo)

        fpr = str(key.fingerprint)
        seckey = self.gpg.export_keys(fpr, secret=True, subkeys=True)
        keyfile = os.path.join(_files, 'test_key_4.sec')
        log.info("Writing generated key to %s" % keyfile)
        with open(keyfile, 'w') as fh:
            fh.write(seckey)
        self.assertTrue(os.path.isfile(keyfile))

    def test_signature_string_bad_passphrase(self):
        """Test that a signing attempt with a bad passphrase fails."""
        key = self.generate_key("Bruce Schneier", "schneier.com",
                                passphrase="correct horse battery staple")
        fpr = key.fingerprint
        message = 'أصحاب المصالح لا يحبون الثوراتز'
        sig = self.gpg.sign(message, default_key=fpr,
                            passphrase='wrong horse battery staple')
        self.assertFalse(sig, "Bad passphrase should fail")

    def test_signature_string_passphrase_empty_string(self):
        """Test that a signing attempt with passphrase='' creates a valid
        signature.

        See Issue #82: https://github.com/isislovecruft/python-gnupg/issues/82
        """
        with open(os.path.join(_files, 'test_key_1.sec')) as fh1:
            res1 = self.gpg.import_keys(fh1.read())
            key1 = res1.fingerprints[0]

        message = 'abc\ndef\n'
        sig = self.gpg.sign(message, default_key=key1, passphrase='')
        self.assertTrue(sig)
        self.assertTrue(message in str(sig))

    def test_signature_string_passphrase_empty_bytes_literal(self):
        """Test that a signing attempt with passphrase=b'' creates a valid
        signature.

        See Issue #82: https://github.com/isislovecruft/python-gnupg/issues/82
        """
        with open(os.path.join(_files, 'test_key_1.sec')) as fh1:
            res1 = self.gpg.import_keys(fh1.read())
            key1 = res1.fingerprints[0]

        message = 'abc\ndef\n'
        sig = self.gpg.sign(message, default_key=key1, passphrase=b'')
        self.assertTrue(sig)
        print("%r" % str(sig))
        self.assertTrue(message in str(sig))

    def test_signature_string_passphrase_bytes_literal(self):
        """Test that a signing attempt with passphrase=b'overalls' creates a
        valid signature.
        """
        with open(os.path.join(_files, 'kat.sec')) as fh1:
            res1 = self.gpg.import_keys(fh1.read())
            key1 = res1.fingerprints[0]

        message = 'abc\ndef\n'
        sig = self.gpg.sign(message, default_key=key1, passphrase=b'overalls')
        self.assertTrue(sig)
        print("%r" % str(sig))
        self.assertTrue(message in str(sig))

    def test_signature_string_passphrase_None(self):
        """Test that a signing attempt with passphrase=None fails creates a
        valid signature.

        See Issue #82: https://github.com/isislovecruft/python-gnupg/issues/82
        """
        with open(os.path.join(_files, 'test_key_1.sec')) as fh1:
            res1 = self.gpg.import_keys(fh1.read())
            key1 = res1.fingerprints[0]

        message = 'abc\ndef\n'
        sig = self.gpg.sign(message, default_key=key1, passphrase=None)
        self.assertTrue(sig)
        self.assertTrue(message in str(sig))

    def test_signature_file(self):
        """Test that signing a message file works."""
        key = self.generate_key("Leonard Adleman", "rsa.com")
        message_file = os.path.join(_files, 'cypherpunk_manifesto')
        with open(message_file) as msg:
            sig = self.gpg.sign(msg, default_key=key.fingerprint,
                                passphrase='leonardadleman')
            self.assertTrue(sig, "I thought I typed my password correctly...")

    def test_signature_string_verification(self):
        """Test verification of a signature from a message string."""
        key = self.generate_key("Bruce Schneier", "schneier.com",
                                passphrase="bruceschneier")
        message  = '...the government uses the general fear of '
        message += '[hackers in popular culture] to push for more power'
        sig = self.gpg.sign(message, default_key=key.fingerprint,
                            passphrase="bruceschneier")
        now = mktime(localtime())
        self.assertTrue(sig, "Good passphrase should succeed")
        verified = self.gpg.verify(sig.data)
        self.assertIsNotNone(verified.fingerprint)
        if key.fingerprint != verified.fingerprint:
            log.warn("key fingerprint:      %r", key.fingerprint)
            log.warn("verified fingerprint: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")
        self.assertEqual(verified.status, 'signature valid')
        self.assertAlmostEqual(int(now), int(verified.timestamp), delta=1000)
        if self.insecure_prng:
            self.assertEqual(
                verified.username,
                u'Bruce Schneier (insecure!) <bruceschneier@schneier.com>')
        else:
            self.assertEqual(verified.username,
                             u'Bruce Schneier <bruceschneier@schneier.com>')

    def test_signature_verification_clearsign(self):
        """Test verfication of an embedded signature."""
        key = self.generate_key("Johan Borst", "rijnda.el")
        message = "You're *still* using AES? Really?"
        sig = self.gpg.sign(message, default_key=key.fingerprint,
                            passphrase='johanborst')
        self.assertTrue(sig, "Good passphrase should succeed")

        try:
            file = _util._make_binary_stream(sig.data, self.gpg._encoding)
            verified = self.gpg.verify_file(file)
        except UnicodeDecodeError: #happens in Python 2.6
            verified = self.gpg.verify_file(io.BytesIO(sig.data))
        if key.fingerprint != verified.fingerprint:
            log.warn("key fingerprint:      %r", key.fingerprint)
            log.warn("verified fingerprint: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint)

    def test_signature_verification_detached(self):
        """Test that verification of a detached signature of a file works."""

        key = self.generate_key("Paulo S.L.M. Barreto", "anub.is")
        datafn = os.path.join(_files, 'cypherpunk_manifesto')
        sigfn = os.path.extsep.join([datafn, 'sig'])

        datafd = open(datafn, 'rb')
        sig = self.gpg.sign(datafd, default_key=key.fingerprint,
                            passphrase='paulos.l.m.barreto',
                            detach=True,
                            clearsign=False)

        self.assertTrue(sig.data, "File signing should succeed")

        sigfd = open(sigfn, 'wb')
        sigfd.write(sig.data)
        sigfd.flush()

        datafd.seek(0)
        sigfd.seek(0)

        verified = self.gpg.verify_file(datafd, sig_file=sigfn)

        if key.fingerprint != verified.fingerprint:
            log.warn("key fingerprint:      %r", key.fingerprint)
            log.warn("verified fingerprint: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint)

        if os.path.isfile(sigfn):
            os.unlink(sigfn)

    def test_signature_verification_detached_binary(self):
        """Test that detached signature verification in binary mode works."""

        key = self.generate_key("Adi Shamir", "rsa.com")
        datafn = os.path.join(_files, 'cypherpunk_manifesto')
        sigfn = os.path.extsep.join([datafn, 'sig'])

        datafd = open(datafn, 'rb')
        data = datafd.read()

        sig = self.gpg.sign(data, default_key=key.fingerprint,
                            passphrase='adishamir',
                            detach=True,
                            binary=True,
                            clearsign=False)

        self.assertTrue(sig.data, "File signing should succeed")

        sigfd = open(sigfn, 'wb')
        sigfd.write(sig.data)
        sigfd.flush()
        sigfd.close()

        self.assertTrue(sigfd.closed, "Sigfile '%s' should be closed" % sigfn)

        datafd.seek(0)
        verification = self.gpg.verify_file(datafd, sig_file=sigfn)

        self.assertTrue(isinstance(verification, gnupg._parsers.Verify))
        self.assertTrue(verification.valid)

        datafd.close()

        if os.path.isfile(sigfn):
            os.unlink(sigfn)

    def test_list_key_sigs(self):
        self.test_list_keys_initial_public()
        gpg = self.gpg
        gpg.import_keys(PUBKEY_FRED_FOO)
        gpg.import_keys(PUBKEY_BOB_BAR)

        result = gpg.list_sigs(PUBKEY_ID_FRED_FOO)

        self.assertEqual(len(result.sigs[u"Fred Foo <fred@foo.com>"]), 2)
        self.assertEqual(list(result.sigs[u"Fred Foo <fred@foo.com>"])[1], PUBKEY_ID_FRED_FOO)
        self.assertEqual(list(result.sigs[u"Fred Foo <fred@foo.com>"])[0], PUBKEY_ID_BOB_BAR)

    def test_check_key_sigs(self):
        self.test_list_keys_initial_public()
        gpg = self.gpg
        gpg.import_keys(PUBKEY_FRED_FOO)

        result = gpg.check_sigs(PUBKEY_ID_FRED_FOO)

        self.assertIn(PUBKEY_ID_FRED_FOO, result.certs[u"Fred Foo <fred@foo.com>"])
        self.assertNotIn(PUBKEY_ID_BOB_BAR, result.certs[u"Fred Foo <fred@foo.com>"])

        gpg.import_keys(PUBKEY_BOB_BAR)
        result = gpg.check_sigs(PUBKEY_ID_FRED_FOO)

        self.assertIn(PUBKEY_ID_FRED_FOO, result.certs[u"Fred Foo <fred@foo.com>"])
        self.assertIn(PUBKEY_ID_BOB_BAR, result.certs[u"Fred Foo <fred@foo.com>"])

    def test_deletion_public_key(self):
        """Test that key deletion for public keys works, and that it leaves the
        corresponding secret key intact.
        """
        key1 = None
        key2 = None

        with open(os.path.join(_files, 'test_key_1.sec')) as fh1:
            res1 = self.gpg.import_keys(fh1.read())
            key1 = res1.fingerprints[0]

        with open(os.path.join(_files, 'test_key_2.sec')) as fh2:
            res2 = self.gpg.import_keys(fh2.read())
            key2 = res2.fingerprints[0]

        public_keys = self.gpg.list_keys()
        self.assertTrue(len(public_keys), 2)

        self.gpg.delete_keys(key1)

        public_keys = self.gpg.list_keys()
        secret_keys = self.gpg.list_keys(secret=True)
        self.assertTrue(len(public_keys), 1)
        self.assertTrue(len(secret_keys), 2)

    def test_deletion_secret_key(self):
        """Test that key deletion for secret keys works, and that it leaves the
        corresponding public key intact.
        """
        key1 = None
        key2 = None

        with open(os.path.join(_files, 'test_key_1.sec')) as fh1:
            res1 = self.gpg.import_keys(fh1.read())
            key1 = res1.fingerprints[0]

        with open(os.path.join(_files, 'test_key_2.sec')) as fh2:
            res2 = self.gpg.import_keys(fh2.read())
            key2 = res2.fingerprints[0]

        public_keys = self.gpg.list_keys()
        secret_keys = self.gpg.list_keys(secret=True)
        self.assertEqual(len(public_keys), 2)
        self.assertEqual(len(secret_keys), 2)

        self.gpg.delete_keys(key1, secret=True)

        public_keys = self.gpg.list_keys()
        secret_keys = self.gpg.list_keys(secret=True)
        self.assertEqual(len(public_keys), 2)
        self.assertEqual(len(secret_keys), 1)

    def test_deletion_subkeys(self):
        """Test that key deletion for subkeys deletes both the public and
        secret portions of the key.
        """
        key1 = None
        key2 = None

        with open(os.path.join(_files, 'test_key_1.sec')) as fh1:
            res1 = self.gpg.import_keys(fh1.read())
            key1 = res1.fingerprints[0]

        with open(os.path.join(_files, 'test_key_2.sec')) as fh2:
            res2 = self.gpg.import_keys(fh2.read())
            key2 = res2.fingerprints[0]

        public_keys = self.gpg.list_keys()
        secret_keys = self.gpg.list_keys(secret=True)
        self.assertEqual(len(public_keys), 2)
        self.assertEqual(len(secret_keys), 2)

        self.gpg.delete_keys(key1, subkeys=True)

        public_keys = self.gpg.list_keys()
        secret_keys = self.gpg.list_keys(secret=True)
        self.assertEqual(len(public_keys), 1)
        self.assertEqual(len(secret_keys), 1)

    def test_encryption(self):
        """Test encryption of a message string"""
        key = self.generate_key("Craig Gentry", "xorr.ox",
                                passphrase="craiggentry")
        gentry = str(key.fingerprint)
        key = self.generate_key("Marten van Dijk", "xorr.ox",
                                passphrase="martenvandijk")
        dijk = str(key.fingerprint)
        gpg = self.gpg
        message = """
In 2010 Riggio and Sicari presented a practical application of homomorphic
encryption to a hybrid wireless sensor/mesh network. The system enables
transparent multi-hop wireless backhauls that are able to perform statistical
analysis of different kinds of data (temperature, humidity, etc.)  coming from
a WSN while ensuring both end-to-end encryption and hop-by-hop
authentication."""
        encrypted = str(gpg.encrypt(message, dijk))
        log.debug("Plaintext: %s" % message)
        log.debug("Encrypted: %s" % encrypted)
        self.assertNotEquals(message, encrypted)

    def _encryption_test_setup(self):
        passphrase = "craiggentry"
        key = self.generate_key("Craig Gentry", "xorr.ox", passphrase=passphrase)
        fpr = str(key.fingerprint)
        gentry = self.gpg.export_keys(key.fingerprint)
        self.gpg.import_keys(gentry)
        message = """
In 2010 Riggio and Sicari presented a practical application of homomorphic
encryption to a hybrid wireless sensor/mesh network. The system enables
transparent multi-hop wireless backhauls that are able to perform statistical
analysis of different kinds of data (temperature, humidity, etc.)  coming from
a WSN while ensuring both end-to-end encryption and hop-by-hop
authentication."""
        return (message, fpr, passphrase)

    def _encryption_test(self, stream_type, message, fingerprint, passphrase):
        stream = stream_type(message)
        encrypted = self.gpg.encrypt(stream, fingerprint).data
        decrypted = self.gpg.decrypt(encrypted, passphrase=passphrase).data

        if isinstance(decrypted, bytes):
            decrypted = decrypted.decode()
        if isinstance(message, bytes):
            message = message.decode()

        self.assertEqual(message, decrypted)

    def test_encryption_of_file_like_objects_io_StringIO(self):
        """Test encryption of file-like object io.StringIO."""
        message, fpr, passphrase = self._encryption_test_setup()

        try:
            from io import StringIO
            if _util._py3k:
                self._encryption_test(StringIO, message, fpr, passphrase)
            else:
                self._encryption_test(StringIO, unicode(message), fpr, passphrase)
        except ImportError:
            pass

    def test_encryption_of_file_like_objects_io_BytesIO(self):
        """Test encryption of file-like object io.BytesIO."""
        message, fpr, passphrase = self._encryption_test_setup()

        try:
            from io import BytesIO
            if _util._py3k:
                self._encryption_test(BytesIO, bytes(message, 'utf-8'), fpr, passphrase)
            else:
                self._encryption_test(BytesIO, message, fpr, passphrase)
        except ImportError:
            pass

    def test_encryption_of_file_like_objects_StringIO_StringIO(self):
        """Test encryption of file-like object StringIO.StringIO (Python2 only)."""
        message, fpr, passphrase = self._encryption_test_setup()

        if not _util._py3k:
            from StringIO import StringIO
            self._encryption_test(StringIO, message, fpr, passphrase)

    def test_encryption_of_file_like_objects_cStringIO_StringIO(self):
        """Test encryption of file-like object cStringIO.StringIO (Python2 only)."""
        message, fpr, passphrase = self._encryption_test_setup()

        if not _util._py3k:
            from cStringIO import StringIO
            self._encryption_test(StringIO, message, fpr, passphrase)

    def test_encryption_alt_encoding(self):
        """Test encryption with latin-1 encoding"""
        key = self.generate_key("Craig Gentry", "xorr.ox",
                                passphrase="craiggentry")
        gentry = str(key.fingerprint)
        key = self.generate_key("Marten van Dijk", "xorr.ox")
        dijk = str(key.fingerprint)
        self.gpg._encoding = 'latin-1'
        data = u'Hello, André!'.encode(self.gpg._encoding)
        encrypted = self.gpg.encrypt(data, gentry)
        edata = str(encrypted.data)
        self.assertNotEqual(data, edata)
        self.assertGreater(len(edata), 0)

    def test_encryption_multi_recipient(self):
        """Test encrypting a message for multiple recipients"""
        riggio = { 'name_real': 'Riggio',
                   'name_email': 'ri@gg.io',
                   'key_type': 'RSA',
                   'key_length': 2048,
                   'key_usage': '',
                   'subkey_type': 'RSA',
                   'subkey_length': 2048,
                   'subkey_usage': 'encrypt,sign',
                   'passphrase': 'victorygin' }

        ## when we don't specify the subkey lengths and the keylength
        ## gets set automatically in gen_key_input(), gpg complains:
        ##
        ##     gpg: keysize invalid; using 1024 bits
        ##
        sicari = { 'name_real': 'Sicari',
                   'name_email': 'si@ca.ri',
                   'key_type': 'RSA',
                   'key_length': 2048,
                   'key_usage': '',
                   'subkey_type': 'RSA',
                   'subkey_length': 2048,
                   'subkey_usage': 'encrypt,sign',
                   'passphrase': 'overalls' }

        riggio_input = self.gpg.gen_key_input(separate_keyring=True, **riggio)
        log.info("Key stored in separate keyring: %s" % self.gpg.temp_keyring)
        riggio = self.gpg.gen_key(riggio_input)
        self.gpg.options = ['--keyring {0}'.format(riggio.keyring)]
        riggio_key = self.gpg.export_keys(riggio.fingerprint)
        self.gpg.import_keys(riggio_key)

        sicari_input = self.gpg.gen_key_input(separate_keyring=True, **sicari)
        log.info("Key stored in separate keyring: %s" % self.gpg.temp_keyring)
        sicari = self.gpg.gen_key(sicari_input)
        self.gpg.options.append('--keyring {0}'.format(sicari.keyring))
        sicari_key = self.gpg.export_keys(sicari.fingerprint)
        self.gpg.import_keys(sicari_key)

        message = """
In 2010 Riggio and Sicari presented a practical application of homomorphic
encryption to a hybrid wireless sensor/mesh network. The system enables
transparent multi-hop wireless backhauls that are able to perform statistical
analysis of different kinds of data (temperature, humidity, etc.) coming from
a WSN while ensuring both end-to-end encryption and hop-by-hop
authentication."""

        if self.gpg.is_gpg2:
            self.gpg.fix_trustdb()

        encrypted = str(self.gpg.encrypt(message,
                                         riggio.fingerprint,
                                         sicari.fingerprint))
        log.debug("Plaintext: %s" % message)
        log.debug("Ciphertext: %s" % encrypted)

        self.assertNotEquals(message, encrypted)
        self.assertIsNotNone(encrypted)
        self.assertGreater(len(encrypted), 0)

    def test_decryption(self):
        """Test decryption"""
        key = self.generate_key("Frey", "fr.ey", passphrase="frey")
        frey_fpr = key.fingerprint
        frey = self.gpg.export_keys(key.fingerprint)
        self.gpg.import_keys(frey)

        key = self.generate_key("Rück", "rü.ck", passphrase="ruck")
        ruck_fpr = key.fingerprint
        ruck = self.gpg.export_keys(key.fingerprint)
        self.gpg.import_keys(ruck)

        message = """
In 2010 Riggio and Sicari presented a practical application of homomorphic
encryption to a hybrid wireless sensor/mesh network. The system enables
transparent multi-hop wireless backhauls that are able to perform statistical
analysis of different kinds of data (temperature, humidity, etc.)  coming from
a WSN while ensuring both end-to-end encryption and hop-by-hop
authentication."""

        encrypted = str(self.gpg.encrypt(message, ruck_fpr))
        decrypted = str(self.gpg.decrypt(encrypted, passphrase="ruck"))

        if message != decrypted:
            log.debug("was: %r" % message)
            log.debug("new: %r" % decrypted)

        self.assertEqual(message, decrypted)

    def test_decryption_with_bytes_literal(self):
        """Test that ``decrypt(encrypt(b'foo'), ...)`` is successful."""
        with open(os.path.join(_files, 'kat.sec')) as katsec:
            self.gpg.import_keys(katsec.read())
        kat = self.gpg.list_keys('kat')[0]['fingerprint']

        message_filename = os.path.join(_files, 'cypherpunk_manifesto')
        with open(message_filename, 'rb') as f:
            output = os.path.join(self.gpg.homedir, 'test-decryption-with-bytes-literal.gpg')
            kwargs = dict(compress_algo='Uncompressed')
            message = b'Dance like a psycho'
            encrypted = self.gpg.encrypt(message, kat, **kwargs)
            self.assertTrue(encrypted.ok)
            self.assertGreater(len(str(encrypted)), 0)

            decrypted = self.gpg.decrypt(encrypted.data, passphrase='overalls')
            self.assertTrue(decrypted.ok)
            self.assertGreater(len(str(decrypted)), 0)
            # Decode the message so that we can easily compare it with the
            # decrypted version in both Python2 and Python3:
            decoded = message.decode(self.gpg._encoding, self.gpg._decode_errors)
            self.assertEqual(str(decrypted), decoded)

    def test_encryption_one_hidden_recipient_one_not(self):
        """Test to ensure hidden recipient isn't detailed in packet info"""

        alice = open(os.path.join(_files, 'test_key_1.pub'))
        alice_pub = alice.read()
        alice_public = self.gpg.import_keys(alice_pub)
        res = alice_public.results[-1:][0]
        alice_pfpr = str(res['fingerprint'])
        alice.close()

        bob = open(os.path.join(_files, 'test_key_2.pub'))
        bob_pub = bob.read()
        bob_public = self.gpg.import_keys(bob_pub)
        res = bob_public.results[-1:][0]
        bob_pfpr = str(res['fingerprint'])
        bob.close()

        message = """
In 2010 Riggio and Sicari presented a practical application of homomorphic
encryption to a hybrid wireless sensor/mesh network. The system enables
transparent multi-hop wireless backhauls that are able to perform statistical
analysis of different kinds of data (temperature, humidity, etc.)  coming from
a WSN while ensuring both end-to-end encryption and hop-by-hop
authentication."""
        enc = self.gpg.encrypt(message, alice_pfpr, bob_pfpr, hidden_recipients=[alice_pfpr])
        encrypted = str(enc)
        log.debug("keyid = %s"
                  % alice_pfpr)

        self.assertNotEquals(message, encrypted)
        ## We expect Alice's key to be hidden (returned as zero's) and Bob's
        ## key to be there.
        expected_values = ["0000000000000000", "E0ED97345F2973D6"]
        self.assertEquals(expected_values, self.gpg.list_packets(encrypted).encrypted_to)

    def test_encryption_throw_keyids(self):
        """Test to ensure throw-keyids=True causes all recipients to be hidden.
        """
        alice = open(os.path.join(_files, 'test_key_1.pub'))
        alice_pub = alice.read()
        alice_public = self.gpg.import_keys(alice_pub)
        res = alice_public.results[-1:][0]
        alice_pfpr = str(res['fingerprint'])
        alice.close()

        bob = open(os.path.join(_files, 'test_key_2.pub'))
        bob_pub = bob.read()
        bob_public = self.gpg.import_keys(bob_pub)
        res = bob_public.results[-1:][0]
        bob_pfpr = str(res['fingerprint'])
        bob.close()

        message = """
Pairing-based cryptography has led to several cryptographic advancements. One
of these advancements is more powerful and more efficient non-interactive
zero-knowledge proofs. The seminal idea was to hide the values for the
evaluation of the pairing in a commitment. Using different commitment schemes,
this idea was used to build zero-knowledge proof systems under the sub-group
hiding and under the decisional linear assumption. These proof systems prove
circuit satisfiability, and thus by the Cook–Levin theorem allow to prove
membership for every language in NP. The size of the common reference string
and the proofs is relatively small, however transforming a statement into a
boolean circuit causes a considerable overhead."""
        enc = self.gpg.encrypt(message, alice_pfpr, bob_pfpr, throw_keyids=True)
        encrypted = str(enc)
        log.debug("keyid = %s"
                  % alice_pfpr)

        self.assertNotEquals(message, encrypted)
        ## We expect Alice's key to be hidden (returned as zero's) and Bob's
        ## key to be there.
        expected_values = ["0000000000000000", "0000000000000000"]
        packets = self.gpg.list_packets(encrypted)
        self.assertEquals(expected_values, packets.encrypted_to)

    def test_encryption_decryption_multi_recipient(self):
        """Test decryption of an encrypted string for multiple users"""

        alice = open(os.path.join(_files, 'test_key_1.pub'))
        alice_pub = alice.read()
        alice_public = self.gpg.import_keys(alice_pub)
        res = alice_public.results[-1:][0]
        alice_pfpr = str(res['fingerprint'])
        alice.close()

        alice = open(os.path.join(_files, 'test_key_1.sec'))
        alice_priv = alice.read()
        alice_private = self.gpg.import_keys(alice_priv)
        res = alice_private.results[-1:][0]
        alice_sfpr = str(res['fingerprint'])
        alice.close()

        bob = open(os.path.join(_files, 'test_key_2.pub'))
        bob_pub = bob.read()
        bob_public = self.gpg.import_keys(bob_pub)
        res = bob_public.results[-1:][0]
        bob_pfpr = str(res['fingerprint'])
        bob.close()

        bob = open(os.path.join(_files, 'test_key_2.sec'))
        bob_priv = bob.read()
        bob_private = self.gpg.import_keys(bob_priv)
        res = bob_public.results[-1:][0]
        bob_sfpr = str(res['fingerprint'])
        bob.close()

        log.debug("alice public fpr: %s" % alice_pfpr)
        log.debug("alice public fpr: %s" % alice_sfpr)
        log.debug("bob public fpr: %s" % bob_pfpr)
        log.debug("bob public fpr: %s" % bob_sfpr)

        message = """
In 2010 Riggio and Sicari presented a practical application of homomorphic
encryption to a hybrid wireless sensor/mesh network. The system enables
transparent multi-hop wireless backhauls that are able to perform statistical
analysis of different kinds of data (temperature, humidity, etc.)  coming from
a WSN while ensuring both end-to-end encryption and hop-by-hop
authentication."""
        enc = self.gpg.encrypt(message, alice_pfpr, bob_pfpr)
        encrypted = str(enc)
        log.debug("encryption_decryption_multi_recipient() Ciphertext = %s"
                  % encrypted)

        self.assertNotEquals(message, encrypted)
        dec_alice = self.gpg.decrypt(encrypted, passphrase="test")

        self.assertEquals(message, str(dec_alice))
        dec_bob = self.gpg.decrypt(encrypted, passphrase="test")
        self.assertEquals(message, str(dec_bob))

    def test_symmetric_encryption_and_decryption(self):
        """Test symmetric encryption and decryption"""
        msg  = """If you have something that you don't want anyone to
know, maybe you shouldn't be doing it in the first place.
-- Eric Schmidt, CEO of Google"""
        encrypted = str(self.gpg.encrypt(msg, passphrase='quiscustodiet',
                                         symmetric=True, encrypt=False))
        decrypt = self.gpg.decrypt(encrypted, passphrase='quiscustodiet')
        decrypted = str(decrypt)

        log.info("Symmetrically encrypted data:\n%s" % encrypted)
        log.info("Symmetrically decrypted data:\n%s" % decrypted)

        self.assertIsNotNone(encrypted)
        self.assertNotEquals(encrypted, "")
        self.assertNotEquals(encrypted, msg)
        self.assertIsNotNone(decrypted)
        self.assertNotEquals(decrypted, "")
        self.assertEqual(decrypted, msg)

    def test_file_encryption_and_decryption(self):
        """Test that encryption/decryption to/from file works."""
        with open(os.path.join(_files, 'kat.sec')) as katsec:
            self.gpg.import_keys(katsec.read())

        kat = self.gpg.list_keys('kat')[0]['fingerprint']

        enc_outf = os.path.join(self.gpg.homedir, 'to-b.gpg')

        # XXX not used atm
        # dec_outf = os.path.join(self.gpg.homedir, 'to-b.txt')

        message_file = os.path.join(_files, 'cypherpunk_manifesto')
        with open(message_file) as msg:
            data = msg.read()
            ## GnuPG seems to ignore the output directive...
            edata = self.gpg.encrypt(data, kat, output=enc_outf)
            with open(enc_outf, 'w+') as enc:
                enc.write(str(edata))

            with open(enc_outf) as enc2:
                fdata = enc2.read()
                ddata = self.gpg.decrypt(fdata, passphrase="overalls").data

                if ddata != data:
                    log.debug("data was: %r" % data)
                    log.debug("new (from filehandle): %r" % fdata)
                    log.debug("new (from decryption): %r" % ddata)
                    self.assertEqual(data, ddata)

    def test_encryption_to_filename(self):
        """Test that ``encrypt(..., output='somefile.gpg')`` is successful."""
        with open(os.path.join(_files, 'kat.sec')) as katsec:
            self.gpg.import_keys(katsec.read())
        fpr = self.gpg.list_keys('kat')[0]['fingerprint']
        output = os.path.join(self.gpg.homedir, 'test-encryption-to-filename.gpg')

        message_filename = os.path.join(_files, 'cypherpunk_manifesto')
        message_file = open(message_filename)
        message = message_file.read()
        message_file.close()

        encrypted = self.gpg.encrypt(message, fpr, output=output)
        self.assertTrue(encrypted.ok)
        self.assertTrue(os.path.isfile(output))

        # Check the contents:
        with open(output, 'rb') as fh:
            encrypted_message = fh.read()
            self.assertTrue(b"-----BEGIN PGP MESSAGE-----" in encrypted_message)

    def test_encryption_to_filehandle(self):
        """Test that ``encrypt(..., output=filelikething)`` is successful."""
        with open(os.path.join(_files, 'kat.sec')) as katsec:
            self.gpg.import_keys(katsec.read())
        fpr = self.gpg.list_keys('kat')[0]['fingerprint']
        output = os.path.join(self.gpg.homedir, 'test-encryption-to-filehandle.gpg')
        output_file = open(output, 'w+')

        message_filename = os.path.join(_files, 'cypherpunk_manifesto')
        message_file = open(message_filename)
        message = message_file.read()
        message_file.close()

        encrypted = self.gpg.encrypt(message, fpr, output=output_file)
        self.assertTrue(encrypted.ok)
        self.assertTrue(os.path.isfile(output))

        # Check the contents:
        with open(output, 'rb') as fh:
            encrypted_message = fh.read()
            self.assertTrue(b"-----BEGIN PGP MESSAGE-----" in encrypted_message)

    def test_encryption_from_filehandle(self):
        """Test that ``encrypt(open('foo'), ...)`` is successful."""
        message_filename = os.path.join(_files, 'cypherpunk_manifesto')
        with open(message_filename, 'rb') as f:
            output = os.path.join(self.gpg.homedir, 'test-encryption-from-filehandle.gpg')
            kwargs = dict(passphrase='speedtest',
                          symmetric=True,
                          cipher_algo='AES256',
                          encrypt=False,
                          output=output)
            encrypted = self.gpg.encrypt(f, None, **kwargs)
            self.assertTrue(encrypted.ok)
            self.assertGreater(len(encrypted.data), 0)

    def test_encryption_with_output(self):
        """Test that ``encrypt('foo', ..., output='/foo/bar/baz')`` is successful."""
        message_filename = os.path.join(_files, 'cypherpunk_manifesto')
        with open (message_filename, 'rb') as f:
            data = f.read()

        output = os.path.join(self.gpg.homedir, 'test-encryption-with-output.gpg')
        kwargs = dict(passphrase='speedtest',
                      symmetric=True,
                      cipher_algo='AES256',
                      encrypt=False,
                      output=output)
        encrypted = self.gpg.encrypt(data, None, **kwargs)
        self.assertTrue(encrypted.ok)
        self.assertGreater(len(encrypted.data), 0)
        self.assertTrue(os.path.isfile(output))

        # Check the contents:
        with open(output, 'rb') as fh:
            encrypted_message = fh.read()
            self.assertTrue(b"-----BEGIN PGP MESSAGE-----" in encrypted_message)

    def test_key_expiration(self):
        """Test that changing key expiration date succeeds."""
        today = datetime.date.today()
        date_format = '%Y-%m-%d'
        tomorrow = today + datetime.timedelta(days=1)
        key = self.generate_key("Haha", "ho.ho", passphrase="haha.hehe", expire_date=tomorrow.strftime(date_format))

        self.gpg.expire(key.fingerprint, expiration_time='1w', passphrase="haha.hehe")
        next_week = today + datetime.timedelta(weeks=1)

        current_keys = self.gpg.list_keys()
        for fecthed_key in current_keys:
            self.assertEqual(next_week, datetime.date.fromtimestamp(int(fecthed_key['expires'])))
            self.assertEqual(key.fingerprint, fecthed_key['fingerprint'])

    def test_passphrase_with_space_on_key_expiration(self):
        """Test that passphrase with space does allow changing expiration."""
        today = datetime.date.today()
        date_format = '%Y-%m-%d'
        tomorrow = today + datetime.timedelta(days=1)
        password_with_space = "passphrase with space"
        key = self.generate_key("Haha", "ho.ho", passphrase=password_with_space,
                                expire_date=tomorrow.strftime(date_format))

        self.gpg.expire(key.fingerprint, expiration_time='1w', passphrase=password_with_space)
        next_week = today + datetime.timedelta(weeks=1)

        current_keys = self.gpg.list_keys()
        for fecthed_key in current_keys:
            self.assertEqual(next_week, datetime.date.fromtimestamp(int(fecthed_key['expires'])))
            self.assertEqual(key.fingerprint, fecthed_key['fingerprint'])

    def test_wrong_passphrase_on_key_expiration(self):
        """Test that wrong passphrase does not allow changing expiration."""
        today = datetime.date.today()
        date_format = '%Y-%m-%d'
        tomorrow = today + datetime.timedelta(days=1)
        key = self.generate_key("Haha", "ho.ho", passphrase="haha.hehe", expire_date=tomorrow.strftime(date_format))

        self.gpg.expire(key.fingerprint, expiration_time='1w', passphrase="wrong passphrase")

        current_keys = self.gpg.list_keys()
        for fecthed_key in current_keys:
            self.assertEqual(tomorrow, datetime.date.fromtimestamp(int(fecthed_key['expires'])))
            self.assertEqual(key.fingerprint, fecthed_key['fingerprint'])

    def test_invalid_expiration_time_throws_exception_on_key_expiration(self):
        """Test that changing key expiration has to be positive value"""
        today = datetime.date.today()
        date_format = '%Y-%m-%d'
        tomorrow = today + datetime.timedelta(days=1)
        key = self.generate_key("Haha", "ho.ho", passphrase="haha.hehe", expire_date=tomorrow.strftime(date_format))

        invalid_expiration_option = "-1w"
        with self.assertRaises(_parsers.UsageError):
            self.gpg.expire(key.fingerprint, expiration_time=invalid_expiration_option, passphrase="haha.hehe")

    def test_key_signing(self):
        """Test that signing a key with default key succeeds."""
        default_key_pair = self.generate_key("haha", "ha.ha", passphrase="haha.haha")
        hehe_key = self.generate_key("hehe", "he.he")

        result = self.gpg.sign_key(hehe_key.fingerprint, passphrase="haha.haha")

        hehe_sigs_keyids = self._get_sigs(hehe_key.fingerprint[-16:])

        self.assertEqual('ok', result.status)
        self.assertIn(default_key_pair.fingerprint[-16:], hehe_sigs_keyids)

    def test_key_signing_with_different_key(self):
        """Test that signing a key with default key succeeds."""
        key1 = self.generate_key("haha", "ha.ha")
        key2 = self.generate_key("hehe", "he.he", passphrase="hehe.hehe")

        result = self.gpg.sign_key(key1.fingerprint, default_key=key2, passphrase="hehe.hehe")

        key1_sigs_keyids = self._get_sigs(key1.fingerprint[-16:])

        self.assertEqual('ok', result.status)
        self.assertIn(key2.fingerprint[-16:], key1_sigs_keyids)

    def _get_sigs(self, target_keyid):
        sigs = self.gpg.list_sigs()
        hehe_sigs = filter(lambda sig: sig['keyid'] == target_keyid, sigs)[0]
        hehe_address = hehe_sigs['uids'][0]     # yields "hehe<hehe@he.he>"
        return map(lambda key: key['keyid'], hehe_sigs['sigs'][hehe_address] )

    def test_signing_an_already_signed_key_does_nothing_and_is_okay(self):
        """Test that re-signing a key does not blow up."""
        default_key_pair = self.generate_key("haha", "ha.ha", passphrase="haha.haha")
        hehe_key = self.generate_key("hehe", "he.he")
        self.gpg.sign_key(hehe_key.fingerprint, passphrase="haha.haha")

        re_sign_result = self.gpg.sign_key(hehe_key.fingerprint, passphrase="haha.haha")

        hehe_sigs_keyids = self._get_sigs(hehe_key.fingerprint[-16:])

        self.assertEqual('ok', re_sign_result.status)
        self.assertIn(default_key_pair.fingerprint[-16:], hehe_sigs_keyids)

    def test_signing_key_with_wrong_password(self):
        """Test signing a key using a wrong password"""
        default_key_pair = self.generate_key("haha", "ha.ha", passphrase="haha.haha")
        hehe_key = self.generate_key("hehe", "he.he")

        wrong_password = "really wrong"
        result = self.gpg.sign_key(hehe_key.fingerprint, passphrase=wrong_password)

        hehe_sigs_keyids = self._get_sigs(hehe_key.fingerprint[-16:])

        self.assertEqual('bad passphrase: %s' % default_key_pair.fingerprint[-16:], result.status)
        self.assertNotIn(default_key_pair.fingerprint[-16:], hehe_sigs_keyids)

suites = { 'parsers': set(['test_parsers_fix_unsafe',
                           'test_parsers_fix_unsafe_semicolon',
                           'test_parsers_is_hex_valid',
                           'test_parsers_is_hex_lowercase',
                           'test_parsers_is_hex_invalid',
                           'test_copy_data_bytesio',]),
           'encodings': set(['test_encodings_big5',
                             'test_encodings_spiteful',
                             'test_encodings_non_specified',]),
           'basic': set(['test_homedir_creation',
                         'test_binary_discovery',
                         'test_gpg_binary',
                         'test_gpg_binary_not_abs',
                         'test_gpg_binary_version_str',
                         'test_gpg_binary_not_installed',
                         'test_list_keys_initial_public',
                         'test_list_keys_initial_secret',
                         'test_make_args_drop_protected_options_gpg_v1',
                         'test_make_args_drop_protected_options_gpg_v2',
                         'test_make_args']),
           'genkey': set(['test_gen_key_input',
                          'test_rsa_key_generation',
                          'test_rsa_key_generation_with_unicode',
                          'test_rsa_key_generation_with_subkey',
                          'test_dsa_key_generation',
                          'test_dsa_key_generation_with_unicode',
                          'test_dsa_key_generation_with_subkey',
                          'test_key_generation_with_invalid_key_type',
                          'test_key_generation_with_empty_value',
                          'test_key_generation_override_default_value',
                          'test_key_generation_with_colons']),
           'sign': set(['test_signature_verification_clearsign',
                        'test_signature_verification_detached',
                        'test_signature_verification_detached_binary',
                        'test_signature_file',
                        'test_signature_string_passphrase_empty_string',
                        'test_signature_string_passphrase_empty_bytes_literal',
                        'test_signature_string_passphrase_bytes_literal',
                        'test_signature_string_passphrase_None',
                        'test_signature_string_bad_passphrase',
                        'test_signature_string_verification',
                        'test_signature_string_algorithm_encoding']),
           'crypt': set(['test_encryption',
                         'test_encryption_of_file_like_objects_io_StringIO',
                         'test_encryption_of_file_like_objects_io_BytesIO',
                         'test_encryption_of_file_like_objects_StringIO_StringIO',
                         'test_encryption_of_file_like_objects_cStringIO_StringIO',
                         'test_encryption_alt_encoding',
                         'test_encryption_multi_recipient',
                         'test_encryption_decryption_multi_recipient',
                         'test_encryption_one_hidden_recipient_one_not',
                         'test_encryption_throw_keyids',
                         'test_decryption',
                         'test_decryption_with_bytes_literal',
                         'test_symmetric_encryption_and_decryption',
                         'test_file_encryption_and_decryption',
                         'test_encryption_to_filename',
                         'test_encryption_to_filehandle',
                         'test_encryption_from_filehandle',
                         'test_encryption_with_output',]),
           'listkeys': set(['test_list_keys_after_generation']),
           'keyrings': set(['test_public_keyring',
                            'test_secret_keyring',
                            'test_import_and_export',
                            'test_deletion_public_key',
                            'test_deletion_secret_key',
                            'test_deletion_subkeys',
                            'test_import_only']),
           'recvkeys': set(['test_recv_keys_default']),
           'revokekey': set(['test_list_revoked_key',
                             'test_revoke_and_not_revoked_key']),
           'expiration': set(['test_key_expiration',
                          'test_passphrase_with_space_on_key_expiration',
                          'test_wrong_passphrase_on_key_expiration',
                          'test_invalid_expiration_time_throws_exception_on_key_expiration']),
           'signing': set(['test_key_signing',
                           'test_key_signing_with_different_key',
                           'test_signing_an_already_signed_key_does_nothing_and_is_okay',
                           'test_signing_key_with_wrong_password']),
}


def main(args):
    if not args.quiet:
        log = _logger.create_logger(9)
        log.setLevel(9)

    loader = unittest.TestLoader()

    def _createTests(prog):
        load_tests = list()
        if args.test is not None:
            for suite in args.test:
                if suite in args.suites.keys():
                    log.debug("Adding %d items from test suite '%s':"
                                 % (len(args.suites[suite]), suite))
                    for method in args.suites[suite]:
                        load_tests.append(method)
                        log.debug("\t%s" % method)
                else:
                    log.debug("Ignoring unknown test suite %r" % suite)
            tests = unittest.TestSuite(list(map(GPGTestCase, load_tests)))
        else:
            tests = prog.testLoader.loadTestsFromTestCase(GPGTestCase)
            args.run_doctest = True
        if args.run_doctest:
            tests.addTest(doctest.DocTestSuite(gnupg))
        log.debug("Loaded %d tests..." % tests.countTestCases())
        prog.test = tests

    runner = unittest.TextTestRunner(verbosity=args.verbose, stream=sys.stderr)
    runner.resultclass = unittest.TextTestResult

    prog = unittest.TestProgram
    prog.createTests = _createTests
    program = prog(module=GPGTestCase,
                   testRunner=runner,
                   testLoader=loader,
                   verbosity=args.verbose,
                   catchbreak=True)

    ## Finally, remove our testing directory:
    if not RETAIN_TEST_DIRS:
        if os.path.isdir(_tempd):
            shutil.rmtree(_tempd)

def before_run():
    if os.path.isdir(_util._here):
        print("_util._here says we're here: %s" % _util._here)
        pattern = os.path.join(_util._here, '*ring')
        rings = glob(pattern)
        if len(rings) > 0:
            for ring in rings:
                fn = os.path.basename(ring)
                genkeysdir = os.path.join(_tests, 'generated-keys')
                try:
                    os.rename(ring, os.path.join(genkeysdir, fn))
                except OSError as err:
                    ## if we can't move the files it won't kill us:
                    log.warn(err)

if __name__ == "__main__":

    before_run()

    suite_names = list()
    for name, methodset in suites.items():
        suite_names.append(name)
        setattr(GPGTestCase, name, list(methodset))

    parser = ArgumentParser(description="Unittests for python-gnupg")
    parser.add_argument('--doctest', dest='run_doctest',
                        type=bool, default=False,
                        help='Run example code in docstrings')
    parser.add_argument('--quiet', dest='quiet',
                        type=bool, default=False,
                        help='Disable logging to stdout')
    parser.add_argument('--verbose', dest='verbose',
                        type=int, default=4,
                        help='Set verbosity level (low=1 high=5) (default: 4)')
    parser.add_argument('test', metavar='test', nargs='+', type=str,
                        help='Select a test suite to run (default: all)')
    parser.epilog = "Available test suites: %s" % " ".join(suite_names)

    args = parser.parse_args()
    args.suites = suites

    sys.exit(main(args))
