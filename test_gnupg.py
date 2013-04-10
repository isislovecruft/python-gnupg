#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A test harness for gnupg.py.

Copyright © 2013 Isis Lovecruft.
Copyright © 2008-2013 Vinay Sajip. All rights reserved.
"""

import argparse
import doctest
import logging
from functools import wraps
import inspect
import io
import os
import shutil
import sys
import tempfile

## Use unittest2 if we're on Python2.6 or less:
if sys.version_info.major == 2 and sys.version_info.minor <= 6:
    unittest = __import__(unittest2)
else:
    import unittest

import gnupg

__author__  = gnupg.__author__
__date__    = gnupg.__date__
__version__ = gnupg.__version__

REPO_DIR = os.getcwd()
HOME_DIR = os.path.join(REPO_DIR, 'keys')

tempfile.tempdir = os.path.join(REPO_DIR, 'tmp_test')
if not os.path.isdir(tempfile.gettempdir()):
    os.mkdir(tempfile.gettempdir())

@wraps(tempfile.TemporaryFile)
def _make_tempfile(*args, **kwargs):
    return tempfile.TemporaryFile(dir=tempfile.gettempdir(),
                                  *args, **kwargs)

logger = logging.getLogger(gnupg.logger.name)

KEYS_TO_IMPORT = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.9 (MingW32)

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
=sqld
-----END PGP PUBLIC KEY BLOCK-----"""


def is_list_with_len(o, n):
    return isinstance(o, list) and len(o) == n

def compare_keys(k1, k2):
    """
    Compare ASCII keys.
    """
    k1 = k1.split('\n')
    k2 = k2.split('\n')
    del k1[1] # remove version lines
    del k2[1]
    return k1 != k2


class ResultStringIO(io.StringIO):
    def __init__(self):
        super(self, io.StringIO).__init__()

    def write(self, data):
        super(self, io.StringIO).write(unicode(data))


class GPGTestCase(unittest.TestCase):
    """
    A group of :class:`unittest.TestCase` unittests for testing python-gnupg.
    """

    @classmethod
    def setUpClass(cls):
        """
        Setup the :class:`GPGTestCase` and runtime environment for tests.

        This function must be called manually.
        xxx or is called by TestSuite.
        """
        pass

    def setUp(self):
        """
        This method is called once per self.test_* method.
        """
        hd = HOME_DIR
        if os.path.exists(hd):
            self.assertTrue(os.path.isdir(hd), "Not a directory: %s" % hd)
            shutil.rmtree(hd)
        self.homedir = hd
        self.gpg = gnupg.GPG(gpghome=hd, gpgbinary='gpg')
        self.pubring = os.path.join(self.homedir, 'pubring.gpg')
        self.secring = os.path.join(self.homedir, 'secring.gpg')

    def test_environment(self):
        """
        Test the environment by ensuring that setup worked.
        """
        hd = self.homedir
        self.assertTrue(os.path.exists(hd) and os.path.isdir(hd),
                        "Not an existing directory: %s" % hd)

    def test_gpg_binary(self):
        """
        Test that 'gpg --version' does not return an error code.
        """
        proc = self.gpg._open_subprocess(['--version'])
        result = io.StringIO()
        self.gpg._collect_output(proc, result, stdin=proc.stdin)
        self.assertEqual(proc.returncode, 0)

    def test_gpg_binary_version_str(self):
        """
        That that 'gpg --version' returns the expected output.
        """
        proc = self.gpg._open_subprocess(['--version'])
        result = proc.stdout.read(1024)
        expected1 = "Supported algorithms:"
        expected2 = "Pubkey:"
        expected3 = "Cipher:"
        expected4 = "Compression:"
        logger.debug("'gpg --version' returned output:n%s" % result)
        self.assertGreater(result.find(expected1), 0)
        self.assertGreater(result.find(expected2), 0)
        self.assertGreater(result.find(expected3), 0)
        self.assertGreater(result.find(expected4), 0)

    def test_gpg_binary_not_abs(self):
        """Test that a non-absolute path to gpg results in a full path."""
        self.assertTrue(os.path.isabs(self.gpg.gpgbinary))

    def test_make_args_drop_protected_options(self):
        """Test that unsupported gpg options are dropped."""
        self.gpg.options = ['--tyrannosaurus-rex', '--stegosaurus']
        self.gpg.keyring = self.secring
        cmd = self.gpg.make_args(None, False)
        expected = ['/usr/bin/gpg',
                    '--status-fd 2 --no-tty',
                    '--homedir "%s"' % os.path.join(os.getcwd(), 'keys'),
                    '--no-default-keyring --keyring %s --secret-keyring %s'
                    % (self.pubring, self.secring)]
        self.assertListEqual(cmd, expected)

    def test_make_args(self):
        """Test argument line construction."""
        not_allowed = ['--bicycle', '--zeppelin', 'train', 'flying-carpet']
        self.gpg.options = not_allowed[:-2]
        args = self.gpg.make_args(not_allowed[2:], False)
        self.assertTrue(len(args) == 4)
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


    def test_copy_data(self):
        """
        XXX implement me
        XXX add me to a test suite

        Test that _copy_data() is able to duplicate byte streams.
        """
        instream = io.BytesIO("This is a string of bytes mapped in memory.")
        outstream = str("And this one is just a string.")

    def generate_key_input(self, real_name, email_domain, key_length=None,
                           key_type=None, subkey_type=None, passphrase=None):
        """Generate a GnuPG batch file for key unattended key creation."""
        name = real_name.lower().replace(' ', '')

        ## XXX will GPG just use it's defaults? does it have defaults if
        ## we've just given it a homedir without a gpg.conf?
        key_type   = 'RSA'if key_type is None else key_type
        key_length = 4096 if key_length is None else key_length

        batch = {'Key-Type': key_type,
                 'Key-Length': key_length,
                 'Name-Comment': 'python-gnupg tester',
                 'Expire-Date': 1,
                 'Name-Real': '%s' % real_name,
                 'Name-Email': ("%s@%s" % (name, email_domain))}

        batch['Passphrase'] = name if passphrase is None else passphrase

        if subkey_type is not None:
            batch['Subkey-Type'] = subkey_type
            batch['Subkey-Length'] = key_length

        key_input = self.gpg.gen_key_input(**batch)
        return key_input

    def generate_key(self, real_name, email_domain, **kwargs):
        """Generate a basic key."""
        key_input = self.generate_key_input(real_name, email_domain, **kwargs)
        key = self.gpg.gen_key(key_input)

    def test_gen_key_input(self):
        """Test that GnuPG batch file creation is successful."""
        key_input = self.generate_key_input("Francisco Ferrer", "an.ok")
        self.assertIsNotNone(key_input)
        self.assertGreater(key_input.find('Francisco Ferrer'), 0)

    def test_rsa_key_generation(self):
        """
        Test that RSA key generation succeeds.
        """
        key = self.generate_key("Barbara Brown", "beta.com")
        self.assertIsNotNone(key)
        self.assertIsNotNone(key.fingerprint)

    def test_rsa_key_generation_with_unicode(self):
        """
        Test that RSA key generation succeeds with unicode characters.
        """
        key = self.generate_key("Anaïs de Flavigny", "êtrerien.fr")
        self.assertIsNotNone(key)
        self.assertIsNotNone(key.fingerprint)

    def test_rsa_key_generation_with_subkey(self):
        """
        Test that RSA key generation succeeds with additional subkey.
        """
        key = self.generate_key("Need Caffeine", "nowplea.se",
                                subkey_type='RSA')
        self.assertIsNotNone(key)
        self.assertIsNotNone(key.fingerprint)

    def test_dsa_key_generation(self):
        """
        Test that DSA key generation succeeds.
        """
        key = self.generate_key("DSA Signonly", "test.com")
        self.assertIsNotNone(key)
        self.assertIsNotNone(key.fingerprint)

    def test_dsa_key_generation_with_unicode(self):
        """
        Test that DSA key generation succeeds with unicode characters.
        """
        key = self.generate_key("破壊合計する", "破壊合計する.日本")
        self.assertIsNotNone(key)
        self.assertIsNotNone(key.fingerprint)

    def test_dsa_key_generation_with_subkey(self):
        """
        Test that RSA key generation succeeds with additional subkey.
        """
        key = self.generate_key("OMG Moar Coffee", "giveitto.me",
                                subkey_type='ELG-E')
        self.assertIsNotNone(key)
        self.assertIsNotNone(key.fingerprint)

    def test_key_generation_with_invalid_key_type(self):
        """
        Test that key generation handles invalid key type.
        """
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
        self.assertIsInstance(key.data, str)
        self.assertEquals(key.data, '')
        self.assertIs(None, key.fingerprint, 'Null fingerprint result')

    def test_key_generation_with_colons(self):
        """
        Test that key generation handles colons in Name fields.
        """
        params = {
            'key_type': 'RSA',
            'name_real': 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19',
            'name_comment': 'dummy comment',
            'name_email': 'test.name@example.com',
        }
        batch = self.gpg.gen_key_input(**params)
        key = self.gpg.gen_key(cmd)
        print "KEY DATA\n", key.data
        print "KEY FINGERPRINT\n", key.fingerprint

    def test_key_generation_import_list_with_colons(self):
        """
        Test that key generation handles colons in Name fields.
        """
        params = {
            'key_type': 'RSA',
            'name_real': 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19',
            'name_comment': 'dummy comment',
            'name_email': 'test.name@example.com',
        }
        batch = self.gpg.gen_key_input(**params)
        key = self.gpg.gen_key(cmd)
        keys = self.gpg.list_keys()
        self.assertIsNotNone(key)
        self.assertEqual(len(keys), 1)
        key = keys[0]
        uids = key['uids']
        self.assertEqual(len(uids), 1)
        uid = uids[0]
        self.assertEqual(uid, 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19 '
                              '(dummy comment) <test.name@example.com>')

    def test_key_generation_with_empty_value(self):
        """
        Test that key generation handles empty values.
        """
        params = {
            'key_type': 'RSA',
            'key_length': 1024,
            'name_comment': ' ', # Not added, so default will appear
        }
        cmd = self.gpg.gen_key_input(**params)
        self.assertTrue('\nName-Comment: Generated by gnupg.py\n' in cmd)
        params['name_comment'] = 'A'
        cmd = self.gpg.gen_key_input(**params)
        self.assertTrue('\nName-Comment: A\n' in cmd)

    def test_list_keys_after_generation(self):
        """
	Test that after key generation, the generated key is available.
	"""
        self.test_list_keys_initial()
        self.do_key_generation()
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 1),
                        "1-element list expected")
        private_keys = self.gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 1),
                        "1-element list expected")

    def test_encryption_and_decryption(self):
        """
	Test that encryption and decryption works.
	"""
        logger.debug("test_encryption_and_decryption begins")
        key = self.generate_key("Andrew", "Able", "alpha.com",
                                passphrase="andy")
        andrew = key.fingerprint
        key = self.generate_key("Barbara", "Brown", "beta.com")
        barbara = key.fingerprint
        gpg = self.gpg
        gpg.encoding = 'latin-1'
        if gnupg._py3k:
            data = 'Hello, André!'
        else:
            data = unicode('Hello, André', gpg.encoding)
        data = data.encode(gpg.encoding)
        edata = str(gpg.encrypt(data, barbara))
        self.assertNotEqual(data, edata, "Data must have changed")
        ddata = gpg.decrypt(edata, passphrase="bbrown")
        if data != ddata.data:
            logger.debug("was: %r", data)
            logger.debug("new: %r", ddata.data)
        self.assertEqual(data, ddata.data, "Round-trip must work")
        edata = str(gpg.encrypt(data, [andrew, barbara]))
        self.assertNotEqual(data, edata, "Data must have changed")
        ddata = gpg.decrypt(edata, passphrase="andy")
        self.assertEqual(data, ddata.data, "Round-trip must work")
        ddata = gpg.decrypt(edata, passphrase="bbrown")
        self.assertEqual(data, ddata.data, "Round-trip must work")
        logger.debug("test_encryption_and_decryption ends")
        # Test symmetric encryption
        data = "chippy was here"
        edata = str(gpg.encrypt(data, None, passphrase='bbrown', symmetric=True))
        ddata = gpg.decrypt(edata, passphrase='bbrown')
        self.assertEqual(data, str(ddata))

    def test_public_keyring(self):
        """
	Test that the public keyring is found in the gpg home directory.
	"""
        self.gpg.keyring = self.pubring
        self.assertTrue(os.path.isfile(self.pubring))

    def test_secret_keyring(self):
        """
	Test that the secret keyring is found in the gpg home directory.
	"""
        self.gpg.keyring = self.secring
        self.assertTrue(os.path.isfile(self.secring))

    def test_import_and_export(self):
        """
	Test that key import and export works.
	"""
        logger.debug("test_import_and_export begins")
        self.test_list_keys_initial()
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
            logger.debug("was: %r", KEYS_TO_IMPORT)
            logger.debug("now: %r", ascii)
        self.assertEqual(0, match, "Keys must match")
        #Generate a key so we can test exporting private keys
        key = self.do_key_generation()
        ascii = gpg.export_keys(key.fingerprint, True)
        self.assertTrue(ascii.find("PGP PRIVATE KEY BLOCK") >= 0,
                        "Exported key should be private")
        logger.debug("test_import_and_export ends")

    def test_import_only(self):
	"""
	Test that key import works.
	"""
        logger.debug("test_import_only begins")
        self.test_list_keys_initial()
        self.gpg.import_keys(KEYS_TO_IMPORT)
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
            logger.debug("was: %r", KEYS_TO_IMPORT)
            logger.debug("now: %r", ascii)
        self.assertEqual(0, match, "Keys must match")
        logger.debug("test_import_only ends")

    def test_signature_verification(self):
        """
	Test that signing and verification works.
	"""
        logger.debug("test_signature_verification begins")
        key = self.generate_key("Andrew", "Able", "alpha.com")
        self.gpg.encoding = 'latin-1'
        if gnupg._py3k:
            data = 'Hello, André!'
        else:
            data = unicode('Hello, André', self.gpg.encoding)
        data = data.encode(self.gpg.encoding)
        sig = self.gpg.sign(data, keyid=key.fingerprint, passphrase='bbrown')
        self.assertFalse(sig, "Bad passphrase should fail")
        sig = self.gpg.sign(data, keyid=key.fingerprint, passphrase='aable')
        self.assertTrue(sig, "Good passphrase should succeed")
        verified = self.gpg.verify(sig.data)
        if key.fingerprint != verified.fingerprint:
            logger.debug("key: %r", key.fingerprint)
            logger.debug("ver: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")
        self.assertEqual(verified.trust_level, verified.TRUST_ULTIMATE)
        self.assertEqual(verified.trust_text, 'TRUST_ULTIMATE')
        if not os.path.exists('random_binary_data'):
            data_file = open('random_binary_data', 'wb')
            data_file.write(os.urandom(5120 * 1024))
            data_file.close()
        data_file = open('random_binary_data', 'rb')
        sig = self.gpg.sign_file(data_file, keyid=key.fingerprint,
                                 passphrase='aable')
        data_file.close()
        self.assertTrue(sig, "File signing should succeed")
        try:
            file = gnupg._make_binary_stream(sig.data, self.gpg.encoding)
            verified = self.gpg.verify_file(file)
        except UnicodeDecodeError: #happens in Python 2.6
            verified = self.gpg.verify_file(io.BytesIO(sig.data))
        if key.fingerprint != verified.fingerprint:
            logger.debug("key: %r", key.fingerprint)
            logger.debug("ver: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")
        data_file = open('random_binary_data', 'rb')
        sig = self.gpg.sign_file(data_file, keyid=key.fingerprint,
                                 passphrase='aable', detach=True)
        data_file.close()
        self.assertTrue(sig, "File signing should succeed")
        try:
            file = gnupg._make_binary_stream(sig.data, self.gpg.encoding)
            verified = self.gpg.verify_file(file, 'random_binary_data')
        except UnicodeDecodeError: #happens in Python 2.6
            verified = self.gpg.verify_file(io.BytesIO(sig.data))
        if key.fingerprint != verified.fingerprint:
            logger.debug("key: %r", key.fingerprint)
            logger.debug("ver: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")
        logger.debug("test_signature_verification ends")

    def test_deletion(self):
        """
	Test that key deletion works.
	"""
        logger.debug("test_deletion begins")
        self.gpg.import_keys(KEYS_TO_IMPORT)
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 2),
                        "2-element list expected, got %d" % len(public_keys))
        self.gpg.delete_keys(public_keys[0]['fingerprint'])
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 1),
                        "1-element list expected, got %d" % len(public_keys))
        logger.debug("test_deletion ends")

    def test_file_encryption_and_decryption(self):
        """
	Test that encryption/decryption to/from file works.
	"""
        logger.debug("test_file_encryption_and_decryption begins")

        encfname = _make_tempfile()
        logger.debug('Created tempfile for encrypted content: %s' % encfname)
        decfname = _make_tempfile()
        logger.debug('Created tempfile for decrypted content: f%s' % decfname)
        # On Windows, if the handles aren't closed, the files can't be deleted
        #os.close(encfno)
        #os.close(decfno)
        try:
            key = self.generate_key("Andrew", "Able", "alpha.com",
                                    passphrase="andy")
            andrew = key.fingerprint
            key = self.generate_key("Barbara", "Brown", "beta.com")
            barbara = key.fingerprint
            data = "Hello, world!"
            file = gnupg._make_binary_stream(data, self.gpg.encoding)
            edata = self.gpg.encrypt_file(file, barbara,
                                          armor=False, output=encfname)
            ddata = self.gpg.decrypt_file(efile, passphrase="bbrown",
                                          output=decfname)
            encfname.seek(0, 0) # can't use os.SEEK_SET in 2.4
            edata = encfname.read()
            ddata = decfname.read()
            data = data.encode(self.gpg.encoding)
            if ddata != data:
                logger.debug("was: %r", data)
                logger.debug("new: %r", ddata)
            self.assertEqual(data, ddata, "Round-trip must work")
        except Exception as exc:
            logger.warn(exc.message)
        logger.debug("test_file_encryption_and_decryption ends")


suites = { 'basic': set(['test_environment',
                         'test_gpg_binary',
                         'test_gpg_binary_not_abs',
                         'test_gpg_binary_version_str',
                         'test_list_keys_initial_public',
                         'test_list_keys_initial_secret',
                         'test_make_args_drop_protected_options',
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
                          'test_key_generation_with_colons']),
           'sign': set(['test_signature_verification']),
           'crypt': set(['test_encryption_and_decryption',
                         'test_file_encryption_and_decryption']),
           'listkeys': set(['test_list_keys_after_generation']),
           'keyrings': set(['test_public_keyring',
                            'test_secret_keyring',
                            'test_import_and_export',
                            'test_deletion']),
           'import': set(['test_import_only']), }

def _init_logging():
    logging.basicConfig(
        level=logging.DEBUG, filename="test_gnupg.log",
        filemode="a",
        format="%(asctime)s %(levelname)-5s %(name)-7s %(threadName)-10s %(message)s")
    logging.captureWarnings(True)
    logging.logThreads = True
    stream_handler = logging.StreamHandler(stream=sys.stdout)
    stream_handler.setLevel(logging.DEBUG)
    logger = gnupg.logger
    logger.addHandler(stream_handler)
    logger.debug("Starting the logger...")

def main(args):
    if not args.quiet:
        _init_logging()

    loader = unittest.TestLoader()

    def _createTests(prog):
        load_tests = list()
        if args.test is not None:
            for suite in args.test:
                if suite in args.suites.keys():
                    logger.debug("Adding %d items from test suite '%s':"
                                 % (len(args.suites[suite]), suite))
                    for method in args.suites[suite]:
                        load_tests.append(method)
                        logger.debug("\t%s" % method)
                else:
                    logger.debug("Ignoring unknown test suite %r" % suite)
            tests = unittest.TestSuite(list(map(GPGTestCase, load_tests)))
        else:
            tests = prog.testLoader.loadTestsFromTestCase(GPGTestCase)
            args.run_doctest = True ## xxx can we set options here?
        if args.run_doctest:
            tests.addTest(doctest.DocTestSuite(gnupg))
        logger.debug("Loaded %d tests..." % tests.countTestCases())
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

if __name__ == "__main__":

    suite_names = list()
    for name, methodset in suites.items():
        suite_names.append(name)
        this_file = inspect.getfile(inspect.currentframe()).split('.', 1)[0]
        #mod = getattr(this_file, '__dict__', None)
        #func = getattr(gnupg.__module__, '__setattr__', None)
        #if func is not None:
        #    func(name, list(methodset))
        setattr(GPGTestCase, name, list(methodset))

    parser = argparse.ArgumentParser(description="Unittests for python-gnupg")
    parser.add_argument('--doctest',
                        dest='run_doctest',
                        type=bool,
                        default=False,
                        help='Run example code in docstrings')
    parser.add_argument('--quiet',
                        dest='quiet',
                        type=bool,
                        default=False,
                        help='Disable logging to stdout')
    parser.add_argument('--verbose',
                        dest='verbose',
                        type=int,
                        default=4,
                        help='Set verbosity level (low=1 high=5) (default: 4)')
    parser.add_argument('test',
                        metavar='test',
                        nargs='+',
                        type=str,
                        help='Select a test suite to run (default: all)')
    parser.epilog = "Available test suites: %s" % " ".join(suite_names)

    args = parser.parse_args()
    args.suites = suites

    sys.exit(main(args))
