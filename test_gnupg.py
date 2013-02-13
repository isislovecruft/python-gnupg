# -*- coding: utf-8 -*-
"""
A test harness for gnupg.py.

Copyright (C) 2008-2013 Vinay Sajip. All rights reserved.
"""
import doctest
import logging
import os.path
import os
import shutil
import sys
import tempfile
import unittest

import gnupg

__author__ = "Vinay Sajip"
__date__  = "$16-Jan-2013 15:23:54$"

ALL_TESTS = True

logger = logging.getLogger(__name__)

KEYS_TO_IMPORT = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.9 (MingW32)

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
=sqld
-----END PGP PUBLIC KEY BLOCK-----"""

def is_list_with_len(o, n):
    return isinstance(o, list) and len(o) == n

def compare_keys(k1, k2):
    "Compare ASCII keys"
    k1 = k1.split('\n')
    k2 = k2.split('\n')
    del k1[1] # remove version lines
    del k2[1]
    return k1 != k2

class GPGTestCase(unittest.TestCase):
    def setUp(self):
        hd = os.path.join(os.getcwd(), 'keys')
        if os.path.exists(hd):
            self.assertTrue(os.path.isdir(hd),
                            "Not a directory: %s" % hd)
            shutil.rmtree(hd)
        self.homedir = hd
        self.gpg = gnupg.GPG(gnupghome=hd, gpgbinary='gpg')

    def test_environment(self):
        "Test the environment by ensuring that setup worked"
        hd = self.homedir
        self.assertTrue(os.path.exists(hd) and os.path.isdir(hd),
                        "Not an existing directory: %s" % hd)

    def test_list_keys_initial(self):
        "Test that initially there are no keys"
        logger.debug("test_list_keys_initial begins")
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 0),
                        "Empty list expected")
        private_keys = self.gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 0),
                        "Empty list expected")
        logger.debug("test_list_keys_initial ends")

    def generate_key(self, first_name, last_name, domain, passphrase=None):
        "Generate a key"
        params = {
            'Key-Type': 'DSA',
            'Key-Length': 1024,
            'Subkey-Type': 'ELG-E',
            'Subkey-Length': 2048,
            'Name-Comment': 'A test user',
            'Expire-Date': 0,
        }
        params['Name-Real'] = '%s %s' % (first_name, last_name)
        params['Name-Email'] = ("%s.%s@%s" % (first_name, last_name, domain)).lower()
        if passphrase is None:
            passphrase = ("%s%s" % (first_name[0], last_name)).lower()
        params['Passphrase'] = passphrase
        cmd = self.gpg.gen_key_input(**params)
        return self.gpg.gen_key(cmd)
    
    def do_key_generation(self):
        "Test that key generation succeeds"
        result = self.generate_key("Barbara", "Brown", "beta.com")
        self.assertNotEqual(None, result, "Non-null result")
        return result

    def test_key_generation_with_invalid_key_type(self):
        "Test that key generation handles invalid key type"
        params = {
            'Key-Type': 'INVALID',
            'Key-Length': 1024,
            'Subkey-Type': 'ELG-E',
            'Subkey-Length': 2048,
            'Name-Comment': 'A test user',
            'Expire-Date': 0,
            'Name-Real': 'Test Name',
            'Name-Email': 'test.name@example.com',
        }
        cmd = self.gpg.gen_key_input(**params)
        result = self.gpg.gen_key(cmd)
        self.assertFalse(result.data, 'Null data result')
        self.assertEqual(None, result.fingerprint, 'Null fingerprint result')

    def test_key_generation_with_colons(self):
        "Test that key generation handles colons in key fields"
        params = {
            'key_type': 'RSA',
            'name_real': 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19',
            'name_comment': 'dummy comment',
            'name_email': 'test.name@example.com',
        }
        cmd = self.gpg.gen_key_input(**params)
        result = self.gpg.gen_key(cmd)
        keys = self.gpg.list_keys()
        self.assertEqual(len(keys), 1)
        key = keys[0]
        uids = key['uids']
        self.assertEqual(len(uids), 1)
        uid = uids[0]
        self.assertEqual(uid, 'urn:uuid:731c22c4-830f-422f-80dc-14a9fdae8c19 '
                              '(dummy comment) <test.name@example.com>')

    def test_key_generation_with_empty_value(self):
        "Test that key generation handles empty values"
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
        "Test that after key generation, the generated key is available"
        self.test_list_keys_initial()
        self.do_key_generation()
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 1),
                        "1-element list expected")
        private_keys = self.gpg.list_keys(secret=True)
        self.assertTrue(is_list_with_len(private_keys, 1),
                        "1-element list expected")

    def test_encryption_and_decryption(self):
        "Test that encryption and decryption works"
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

    def test_import_and_export(self):
        "Test that key import and export works"
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
        "Test that key import works"
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
        "Test that signing and verification works"
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
            from io import BytesIO
            verified = self.gpg.verify_file(BytesIO(sig.data))
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
            from io import BytesIO
            verified = self.gpg.verify_file(BytesIO(sig.data))
        if key.fingerprint != verified.fingerprint:
            logger.debug("key: %r", key.fingerprint)
            logger.debug("ver: %r", verified.fingerprint)
        self.assertEqual(key.fingerprint, verified.fingerprint,
                         "Fingerprints must match")
        logger.debug("test_signature_verification ends")

    def test_deletion(self):
        "Test that key deletion works"
        logger.debug("test_deletion begins")
        self.gpg.import_keys(KEYS_TO_IMPORT)
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 2),
                        "2-element list expected")
        self.gpg.delete_keys(public_keys[0]['fingerprint'])
        public_keys = self.gpg.list_keys()
        self.assertTrue(is_list_with_len(public_keys, 1),
                        "1-element list expected")
        logger.debug("test_deletion ends")

    def test_nogpg(self):
        "Test that absence of gpg is handled correctly"
        self.assertRaises(ValueError, gnupg.GPG, gnupghome=self.homedir,
                          gpgbinary='frob')

    def test_make_args(self):
        "Test argument line construction"
        self.gpg.options = ['--foo', '--bar']
        args = self.gpg.make_args(['a', 'b'], False)
        self.assertTrue(len(args) > 4)
        self.assertEqual(args[-4:], ['--foo', '--bar', 'a', 'b'])

    def test_file_encryption_and_decryption(self):
        "Test that encryption/decryption to/from file works"
        logger.debug("test_file_encryption_and_decryption begins")
        encfno, encfname = tempfile.mkstemp()
        decfno, decfname = tempfile.mkstemp()
        # On Windows, if the handles aren't closed, the files can't be deleted
        os.close(encfno)
        os.close(decfno)
        logger.debug('Encrypting to: %r', encfname)
        logger.debug('Decrypting to: %r', decfname)
        try:
            key = self.generate_key("Andrew", "Able", "alpha.com",
                                    passphrase="andy")
            andrew = key.fingerprint
            key = self.generate_key("Barbara", "Brown", "beta.com")
            barbara = key.fingerprint
            data = "Hello, world!"
            file = gnupg._make_binary_stream(data, self.gpg.encoding)
            edata = self.gpg.encrypt_file(file,
                                          barbara,
                                          armor=False, output=encfname)
            efile = open(encfname, 'rb')
            ddata = self.gpg.decrypt_file(efile, passphrase="bbrown",
                                          output=decfname)
            efile.seek(0, 0) # can't use os.SEEK_SET in 2.4
            edata = efile.read()
            efile.close()
            dfile = open(decfname, 'rb')
            ddata = dfile.read()
            dfile.close()
            data = data.encode(self.gpg.encoding)
            if ddata != data:
                logger.debug("was: %r", data)
                logger.debug("new: %r", ddata)
            self.assertEqual(data, ddata, "Round-trip must work")
        finally:
            for fn in (encfname, decfname):
                if os.path.exists(fn):
                    os.remove(fn)
        logger.debug("test_file_encryption_and_decryption ends")


TEST_GROUPS = {
    'sign' : set(['test_signature_verification']),
    'crypt' : set(['test_encryption_and_decryption',
                   'test_file_encryption_and_decryption']),
    'key' : set(['test_deletion', 'test_import_and_export',
                 'test_list_keys_after_generation',
                 'test_key_generation_with_invalid_key_type',
                 'test_key_generation_with_empty_value',
                 'test_key_generation_with_colons']),
    'import' : set(['test_import_only']),
    'basic' : set(['test_environment', 'test_list_keys_initial',
                   'test_nogpg', 'test_make_args']),
}

def suite(args=None):
    if args is None:
        args = sys.argv[1:]
    if not args:
        result = unittest.TestLoader().loadTestsFromTestCase(GPGTestCase)
        want_doctests = True
    else:
        tests = set()
        want_doctests = False
        for arg in args:
            if arg in TEST_GROUPS:
                tests.update(TEST_GROUPS[arg])
            elif arg == "doc":
                want_doctests = True
            else:
                print("Ignoring unknown test group %r" % arg)        
        result = unittest.TestSuite(list(map(GPGTestCase, tests)))
    if want_doctests:
        result.addTest(doctest.DocTestSuite(gnupg))
    return result

def init_logging():
    logging.basicConfig(level=logging.DEBUG, filename="test_gnupg.log",
                        filemode="w", format="%(asctime)s %(levelname)-5s %(name)-10s %(threadName)-10s %(message)s")

def main():
    init_logging()
    tests = suite()
    results = unittest.TextTestRunner(verbosity=2).run(tests)
    return not results.wasSuccessful()


if __name__ == "__main__":
    sys.exit(main())
