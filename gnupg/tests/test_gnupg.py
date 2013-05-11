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
import io
import os
import shutil
import sys
import tempfile
import time

## Use unittest2 if we're on Python2.6 or less:
if sys.version_info.major == 2 and sys.version_info.minor <= 6:
    unittest = __import__(unittest2)
else:
    import unittest

import gnupg
from gnupg import parsers
from gnupg import util

__author__  = gnupg.__author__
__version__ = gnupg.__version__


logger = logging.getLogger('gnupg')
_here  = os.path.join(os.path.join(util._repo, 'gnupg'), 'tests')
_files = os.path.join(_here, 'files')
_tempd = os.path.join(_here, 'tmp')

tempfile.tempdir = _tempd
if not os.path.isdir(tempfile.gettempdir()):
    os.mkdir(tempfile.gettempdir())

@wraps(tempfile.TemporaryFile)
def _make_tempfile(*args, **kwargs):
    return tempfile.TemporaryFile(dir=tempfile.gettempdir(),
                                  *args, **kwargs)


KEYS_TO_IMPORT = """-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=sqld
-----END PGP PUBLIC KEY BLOCK-----"""


def is_list_with_len(o, n):
    return isinstance(o, list) and len(o) == n

def compare_keys(k1, k2):
    """Compare ASCII keys."""
    k1 = k1.split('\n')
    k2 = k2.split('\n')
    return k1 != k2


class ResultStringIO(io.StringIO):
    def __init__(self, init_string):
        super(ResultStringIO, self).__init__(init_string)
    def write(self, data):
        super(ResultStringIO, self).write(unicode(data))


class GPGTestCase(unittest.TestCase):
    """:class:`unittest.TestCase <TestCase>`s for python-gnupg."""

    @classmethod
    def setUpClass(cls):
        """Setup ``GPGTestCase`` and runtime environment for tests.

        This function must be called manually.
        """
        pass

    def setUp(self):
        """This method is called once per self.test_* method."""
        hd = tempfile.mkdtemp()
        if os.path.exists(hd):
            self.assertTrue(os.path.isdir(hd), "Not a directory: %s" % hd)
            shutil.rmtree(hd)
        self.homedir = hd
        self.gpg = gnupg.GPG(homedir=hd, binary='gpg')
        self.keyring = os.path.join(self.homedir, 'keyring.gpg')
        self.secring = os.path.join(self.homedir, 'secring.gpg')

    def tearDown(self):
        """This is called once per self.test_* method after the test run."""
        if os.path.exists(self.homedir) and os.path.isdir(self.homedir):
            try:
                shutil.rmtree(self.homedir)
            except OSError as ose:
                logger.error(ose)
        else:
            logger.warn("Can't delete homedir: '%s' not a directory"
                        % self.homedir)

    def test_parsers_fix_unsafe(self):
        """Test that unsafe inputs are quoted out and then ignored."""
        shell_input = "\"&coproc /bin/sh\""
        fixed = parsers._fix_unsafe(shell_input)
        print fixed
        test_file = os.path.join(_files, 'cypherpunk_manifesto')
        self.assertTrue(os.path.isfile(test_file))
        has_shell = self.gpg.verify_file(test_file, fixed)
        self.assertFalse(has_shell.valid)

    def test_parsers_is_hex_valid(self):
        """Test that valid hexidecimal passes the parsers._is_hex() check"""
        valid_hex = '0A6A58A14B5946ABDE18E207A3ADB67A2CDB8B35'
        self.assertTrue(parsers._is_hex(valid_hex))

    def test_parsers_is_hex_lowercase(self):
        """Test parsers._is_hex() with lowercased hexidecimal"""
        valid_hex = 'deadbeef15abad1dea'
        self.assertTrue(parsers._is_hex(valid_hex))

    def test_parsers_is_hex_invalid(self):
        """Test that invalid hexidecimal fails the parsers._is_hex() check"""
        invalid_hex = 'cipherpunks write code'
        self.assertFalse(parsers._is_hex(invalid_hex))

    def test_gpghome_creation(self):
        """Test the environment by ensuring that setup worked."""
        hd = self.homedir
        self.assertTrue(os.path.exists(hd) and os.path.isdir(hd),
                        "Not an existing directory: %s" % hd)

    def test_gpg_binary(self):
        """Test that 'gpg --version' does not return an error code."""
        proc = self.gpg._open_subprocess(['--version'])
        result = io.StringIO()
        self.gpg._collect_output(proc, result, stdin=proc.stdin)
        self.assertEqual(proc.returncode, 0)

    def test_gpg_binary_version_str(self):
        """That that 'gpg --version' returns the expected output."""
        proc = self.gpg._open_subprocess(['--version'])
        result = proc.stdout.read(1024)
        expected1 = "Supported algorithms:"
        expected2 = "Pubkey:"
        expected3 = "Cipher:"
        expected4 = "Compression:"
        #logger.debug("'gpg --version' returned output:n%s" % result)
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
        self.assertTrue(os.path.isabs(self.gpg.binary))

    def test_make_args_drop_protected_options(self):
        """Test that unsupported gpg options are dropped."""
        self.gpg.options = ['--tyrannosaurus-rex', '--stegosaurus']
        cmd = self.gpg._make_args(None, False)
        expected = ['/usr/bin/gpg',
                    '--status-fd 2 --no-tty --no-emit-version',
                    '--homedir "%s"' % self.homedir,
                    '--no-default-keyring --keyring %s' % self.keyring,
                    '--secret-keyring %s' % self.secring,
                    '--no-use-agent',]
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
        message = "This is a BytesIO string string in memory."
        instream = io.BytesIO(message)
        self.assertEqual(unicode(message), instream.getvalue())
        outstream = ResultStringIO(u'result:')
        copied = outstream
        util._copy_data(instream, outstream)
        self.assertTrue(outstream.readable())
        self.assertTrue(outstream.closed)
        self.assertFalse(instream.closed)
        self.assertTrue(copied.closed)
        #self.assertEqual(instream.getvalue()[6:], outstream.getvalue())

    def generate_key_input(self, real_name, email_domain, key_length=None,
                           key_type=None, subkey_type=None, passphrase=None):
        """Generate a GnuPG batch file for key unattended key creation."""
        name = real_name.lower().replace(' ', '')

        key_type   = 'RSA'if key_type is None else key_type
        key_length = 1024 if key_length is None else key_length

        batch = {'Key-Type': key_type,
                 'Key-Length': key_length,
                 'Expire-Date': 1,
                 'Name-Real': '%s' % real_name,
                 'Name-Email': ("%s@%s" % (name, email_domain))}

        batch['Passphrase'] = name if passphrase is None else passphrase

        if subkey_type is not None:
            batch['Subkey-Type'] = subkey_type
            batch['Subkey-Length'] = key_length

        key_input = self.gpg.gen_key_input(testing=True, **batch)
        return key_input

    def generate_key(self, real_name, email_domain, **kwargs):
        """Generate a basic key."""
        key_input = self.generate_key_input(real_name, email_domain, **kwargs)
        key = self.gpg.gen_key(key_input)
        print "\nKEY TYPE: ", key.type
        print "KEY FINGERPRINT: ", key.fingerprint
        return key

    def test_gen_key_input(self):
        """Test that GnuPG batch file creation is successful."""
        key_input = self.generate_key_input("Francisco Ferrer", "an.ok")
        self.assertIsInstance(key_input, str)
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
        self.assertIsNotNone(key.type)
        self.assertIsNotNone(key.fingerprint)
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

    def test_import_and_export(self):
        """Test that key import and export works."""
        logger.debug("test_import_and_export begins")
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
            logger.debug("was: %r", KEYS_TO_IMPORT)
            logger.debug("now: %r", ascii)
        self.assertEqual(0, match, "Keys must match")

        #Generate a key so we can test exporting private keys
        key = self.generate_key('Shai Halevi', 'xorr.ox')
        ascii = gpg.export_keys(key.fingerprint, True)
        self.assertTrue(ascii.find("PGP PRIVATE KEY BLOCK") >= 0,
                        "Exported key should be private")
        logger.debug("test_import_and_export ends")

    def test_import_only(self):
	"""Test that key import works."""
        logger.debug("test_import_only begins")
        self.test_list_keys_initial_public()
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

    def test_signature_string(self):
        """Test that signing a message string works."""
        key = self.generate_key("Werner Koch", "gnupg.org")
        message = "Damn, I really wish GnuPG had ECC support."
        sig = self.gpg.sign(message, keyid=key.fingerprint,
                            passphrase='wernerkoch')
        print "SIGNATURE:\n", sig.data
        self.assertIsNotNone(sig.data)

    def test_signature_algorithm(self):
        """Test that determining the signing algorithm works."""
        key = self.generate_key("Ron Rivest", "rsa.com")
        message = "Someone should add GCM block cipher mode to PyCrypto."
        sig = self.gpg.sign(message, keyid=key.fingerprint,
                            passphrase='ronrivest')
        print "ALGORITHM:\n", sig.sig_algo
        self.assertIsNotNone(sig.sig_algo)

    def test_signature_string_bad_passphrase(self):
        """Test that signing and verification works."""
        key = self.generate_key("Taher ElGamal", "cryto.me")
        message = 'أصحاب المصالح لا يحبون الثوراتز'
        sig = self.gpg.sign(message, keyid=key.fingerprint, passphrase='foo')
        self.assertFalse(sig, "Bad passphrase should fail")

    def test_signature_string_alternate_encoding(self):
        key = self.generate_key("Nos Oignons", "nos-oignons.net")
        self.gpg.encoding = 'latin-1'
        message = "Mêle-toi de tes oignons"
        sig = self.gpg.sign(message, keyid=key.fingerprint,
                            passphrase='nosoignons')
        self.assertTrue(sig)

    def test_signature_file(self):
        """Test that signing a message file works."""
        key = self.generate_key("Leonard Adleman", "rsa.com")
        message_file = os.path.join(_files, 'cypherpunk_manifesto')
        with open(message_file) as msg:
            sig = self.gpg.sign(msg, keyid=key.fingerprint,
                                passphrase='leonardadleman')
            self.assertTrue(sig, "I thought I typed my password correctly...")

    def test_signature_string_verification(self):
        """Test verification of a signature from a message string."""
        key = self.generate_key("Bruce Schneier", "schneier.com")
        message  = '...the government uses the general fear of '
        message += '[hackers in popular culture] to push for more power'
        sig = self.gpg.sign(message, keyid=key.fingerprint,
                            passphrase='bruceschneier')
        now = time.mktime(time.gmtime())
        self.assertTrue(sig, "Good passphrase should succeed")
        verified = self.gpg.verify(sig.data)
        self.assertIsNotNone(verified.fingerprint)
        if key.fingerprint != verified.fingerprint:
            logger.debug("key: %r", key.fingerprint)
            logger.debug("ver: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")
        self.assertEqual(verified.status, 'signature valid')
        self.assertAlmostEqual(int(now), int(verified.timestamp), delta=1000)
        self.assertEqual(
            verified.username,
            u'Bruce Schneier (insecure!) <bruceschneier@schneier.com>')

    def test_signature_verification_clearsign(self):
        """Test verfication of an embedded signature."""
        key = self.generate_key("Johan Borst", "rijnda.el")
        message = "You're *still* using AES? Really?"
        sig = self.gpg.sign(message, keyid=key.fingerprint,
                            passphrase='johanborst')
        self.assertTrue(sig, "Good passphrase should succeed")
        try:
            file = util._make_binary_stream(sig.data, self.gpg.encoding)
            verified = self.gpg.verify_file(file)
        except UnicodeDecodeError: #happens in Python 2.6
            verified = self.gpg.verify_file(io.BytesIO(sig.data))
        if key.fingerprint != verified.fingerprint:
            logger.debug("key: %r", key.fingerprint)
            logger.debug("ver: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")

    def test_signature_verification_detached(self):
        """Test that verification of a detached signature of a file works."""
        key = self.generate_key("Paulo S.L.M. Barreto", "anub.is")
        with open(os.path.join(_files, 'cypherpunk_manifesto'),
                  'rb') as manifesto:
            sig = self.gpg.sign(manifesto, keyid=key.fingerprint,
                                passphrase='paulos.l.m.barreto',
                                detach=True, clearsign=False)
            self.assertTrue(sig.data, "File signing should succeed")
            sigfilename = os.path.join(_files, 'cypherpunk_manifesto.sig')
            with open(sigfilename,'w') as sigfile:
                sigfile.write(sig.data)
                sigfile.seek(0)

            verified = self.gpg.verify_file(manifesto, sigfilename)

            if key.fingerprint != verified.fingerprint:
                logger.debug("key: %r", key.fingerprint)
                logger.debug("ver: %r", verified.fingerprint)

            self.assertEqual(key.fingerprint, verified.fingerprint,
                             "Fingerprints must match")

    def test_signature_verification_detached_binary(self):
        """Test that detached signature verification in binary mode fails."""
        key = self.generate_key("Adi Shamir", "rsa.com")
        with open(os.path.join(_files, 'cypherpunk_manifesto'),
                  'rb') as manifesto:
            sig = self.gpg.sign(manifesto, keyid=key.fingerprint,
                                passphrase='adishamir',
                                detach=True, binary=True, clearsign=False)
            self.assertTrue(sig.data, "File signing should succeed")
            with self.assertRaises(UnicodeDecodeError):
                print "SIG=", sig

    def test_deletion(self):
        """Test that key deletion works."""
        self.gpg.import_keys(KEYS_TO_IMPORT)
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 2),
                        "2-element list expected, got %d" % len(public_keys))
        self.gpg.delete_keys(public_keys[0]['fingerprint'])
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 1),
                        "1-element list expected, got %d" % len(public_keys))
        logger.debug("test_deletion ends")

    def test_encryption(self):
        """Test encryption of a message string."""
        key = self.generate_key("Craig Gentry", "xorr.ox",
                                passphrase="craiggentry")
        gentry = key.fingerprint
        key = self.generate_key("Marten van Dijk", "xorr.ox")
        dijk = key.fingerprint
        gpg = self.gpg
        message = ("In 2010 Riggio and Sicari presented a practical application"
                   " of homomorphic encryption to a hybrid wireless sensor/mesh"
                   " network. The system enables transparent multi-hop wireless"
                   " backhauls that are able to perform statistical analysis of"
                   " different kinds of data (temperature, humidity, etc.) "
                   "coming from a WSN while ensuring both end-to-end encryption"
                   "and hop-by-hop authentication.")
        encrypted = str(gpg.encrypt(message, dijk))
        self.assertNotEqual(message, encrypted, "Data must have changed")

    def test_encryption_alt_encoding(self):
        """Test encryption with latin-1 encoding"""
        key = self.generate_key("Craig Gentry", "xorr.ox",
                                passphrase="craiggentry")
        gentry = key.fingerprint
        key = self.generate_key("Marten van Dijk", "xorr.ox")
        dijk = key.fingerprint
        gpg = self.gpg
        gpg.encoding = 'latin-1'
        if util._py3k:
            data = 'Hello, André!'
        else:
            data = unicode('Hello, André', gpg.encoding)
        data = data.encode(gpg.encoding)
        encrypted = str(gpg.encrypt(data, gentry))
        self.assertNotEqual(data, encrypted, "Data must have changed")

    def test_encryption_multi_recipient(self):
        """Test encrypting a message for multiple recipients"""
        key = self.generate_key("Craig Gentry", "xorr.ox",
                                passphrase="craiggentry")
        gentry = key.fingerprint
        key = self.generate_key("Marten van Dijk", "xorr.ox")
        dijk = key.fingerprint
        gpg = self.gpg
        message = ("In 2010 Riggio and Sicari presented a practical application"
                   " of homomorphic encryption to a hybrid wireless sensor/mesh"
                   " network. The system enables transparent multi-hop wireless"
                   " backhauls that are able to perform statistical analysis of"
                   " different kinds of data (temperature, humidity, etc.) "
                   "coming from a WSN while ensuring both end-to-end encryption"
                   "and hop-by-hop authentication.")
        encrypted2 = str(gpg.encrypt(message, [gentry, dijk]))
        self.assertNotEqual(message, encrypted2, "PT and CT should not match")

    def test_decryption(self):
        """Test decryption"""
        key = self.generate_key("Craig Gentry", "xorr.ox",
                                passphrase="craiggentry")
        gentry = key.fingerprint
        key = self.generate_key("Marten van Dijk", "xorr.ox")
        dijk = key.fingerprint
        gpg = self.gpg
        message = ("In 2010 Riggio and Sicari presented a practical application"
                   " of homomorphic encryption to a hybrid wireless sensor/mesh"
                   " network. The system enables transparent multi-hop wireless"
                   " backhauls that are able to perform statistical analysis of"
                   " different kinds of data (temperature, humidity, etc.) "
                   "coming from a WSN while ensuring both end-to-end encryption"
                   "and hop-by-hop authentication.")
        encrypted = str(gpg.encrypt(message, dijk))
        decrypted = self.gpg.decrypt(encrypted, passphrase="martenvandijk")
        if message != decrypted.data:
            logger.debug("was: %r", message)
            logger.debug("new: %r", decrypted.data)
        self.assertEqual(message, decrypted.data, "Round-trip must work")

        encrypted2 = str(gpg.encrypt(message, [gentry, dijk]))
        self.assertNotEqual(message, encrypted2, "PT and CT should not match")
        decrypted1 = gpg.decrypt(encrypted2, passphrase="craiggentry")
        self.assertEqual(message, decrypted.data, "Round-trip must work")
        decrypted2 = gpg.decrypt(encrypted2, passphrase="martenvandijk")
        self.assertEqual(message, decrypted.data, "Round-trip must work")
        # Test symmetric encryption
        data = "chippy was here"
        edata = str(gpg.encrypt(data, None, passphrase='bbrown',
                                symmetric=True))
        decrypted = gpg.decrypt(edata, passphrase='bbrown')
        self.assertEqual(data, str(decrypted))

    def test_file_encryption_and_decryption(self):
        """Test that encryption/decryption to/from file works."""
        encfname = _make_tempfile()
        logger.debug('Created tempfile for encrypted content: %s' % encfname)
        decfname = _make_tempfile()
        logger.debug('Created tempfile for decrypted content: f%s' % decfname)
        # On Windows, if the handles aren't closed, the files can't be deleted
        #os.close(encfno)
        #os.close(decfno)
        try:
            key = self.generate_key("Andrew Able", "alpha.com",
                                    passphrase="andy")
            andrew = key.fingerprint
            key = self.generate_key("Barbara Brown", "beta.com")
            barbara = key.fingerprint
            data = "Hello, world!"
            file = util._make_binary_stream(data, self.gpg.encoding)
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


suites = { 'parsers': set(['test_parsers_fix_unsafe',
                           'test_parsers_is_hex_valid',
                           'test_parsers_is_hex_lowercase',
                           'test_parsers_is_hex_invalid',
                           'test_copy_data_bytesio',]),
           'basic': set(['test_homedir_creation',
                         'test_binary_discovery',
                         'test_gpg_binary',
                         'test_gpg_binary_not_abs',
                         'test_gpg_binary_version_str',
                         'test_gpg_binary_not_installed',
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
                          'test_key_generation_override_default_value',
                          'test_key_generation_with_colons']),
           'sign': set(['test_signature_verification_clearsign',
                        'test_signature_verification_detached',
                        'test_signature_verification_detached_binary',
                        'test_signature_file',
                        'test_signature_string_bad_passphrase',
                        'test_signature_string_alternate_encoding',
                        'test_signature_string_verification',
                        'test_signature_algorithm',
                        'test_signature_string']),
           'crypt': set(['test_encryption',
                         'test_encryption_alt_encoding',
                         'test_encryption_multi_recipient',
                         'test_decryption',
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

    ## Finally, remove our testing directory:
    if os.path.isdir(_tempd):
        os.unlink(_tempd)

if __name__ == "__main__":

    suite_names = list()
    for name, methodset in suites.items():
        suite_names.append(name)
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
