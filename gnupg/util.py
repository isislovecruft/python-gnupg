#!/usr/bin/env python
#-*- encoding: utf-8 -*-
#
# This file is part of python-gnupg, a Python wrapper around GnuPG.
# Copyright © 2013 Isis Lovecruft, Andrej B.
#           © 2008-2012 Vinay Sajip
#           © 2005 Steve Traugott
#           © 2004 A.M. Kuchling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
'''
utils.py
----------
Extra utilities for python-gnupg.
'''

from gnupg import __author__
from gnupg import __version__
__module__ = 'gnupg.util'

from datetime   import datetime

import logging
import os

try:
    from io import StringIO
    from io import BytesIO
except ImportError:
    from cStringIO import StringIO

try:
    from logging import NullHandler
except:
    class NullHandler(logging.Handler):
        def handle(self, record):
            pass
logger = logging.getLogger('gnupg')
if not logger.handlers:
    logger.addHandler(NullHandler())

try:
    unicode
    _py3k = False
except NameError:
    _py3k = True

## Directory shortcuts:
_here = os.getcwd()                           ## .../python-gnupg/gnupg
_repo = _here.rsplit(__module__, 1)[0]        ## .../python-gnupg
_test = os.path.join(_repo, 'tmp_test')       ## .../python-gnupg/tmp_test
_user = os.environ.get('HOME')                ## $HOME
_ugpg = os.path.join(_user, '.gnupg')         ## $HOME/.gnupg
_conf = os.path.join(os.path.join(_user, '.config'),
                     'python-gnupg')          ## $HOME/.config/python-gnupg

def _create_gpghome(gpghome):
    """Create the specified GnuPG home directory, if necessary.

    :param str gpghome: The directory to use.
    :rtype: bool
    :returns: True if no errors occurred and the directory was created or
              existed beforehand, False otherwise.
    """
    ## xxx how will this work in a virtualenv?
    if not os.path.isabs(gpghome):
        message = ("Got non-abs gpg home dir path: %s" % gpghome)
        logger.warn("util._create_gpghome(): %s" % message)
        gpghome = os.path.abspath(gpghome)
    if not os.path.isdir(gpghome):
        message = ("Creating gpg home dir: %s" % gpghome)
        logger.warn("util._create_gpghome(): %s" % message)
        try:
            os.makedirs(gpghome, 0x1C0)
        except OSError as ose:
            logger.error(ose, exc_info=1)
            return False
        else:
            return True
    else:
        return True

def _find_gpgbinary(gpgbinary=None):
    """Find the absolute path to the GnuPG binary.

    Also run checks that the binary is not a symlink, and check that
    our process real uid has exec permissions.

class ListPackets():
    """
    Handle status messages for --list-packets.
    """

    def __init__(self, gpg):
        self.gpg = gpg
        self.nodata = None
        self.key = None
        self.need_passphrase = None
        self.need_passphrase_sym = None
        self.userid_hint = None

    def handle_status(self, key, value):
        # TODO: write tests for handle_status
        if key == 'NODATA':
            self.nodata = True
        if key == 'ENC_TO':
            # This will only capture keys in our keyring. In the future we
            # may want to include multiple unknown keys in this list.
            self.key, _, _ = value.split()
        if key == 'NEED_PASSPHRASE':
            self.need_passphrase = True
        if key == 'NEED_PASSPHRASE_SYM':
            self.need_passphrase_sym = True
        if key == 'USERID_HINT':
            self.userid_hint = value.strip().split()


class GPGWrapper(gnupg.GPG):
    """
    This is a temporary class for handling GPG requests, and should be
    replaced by a more general class used throughout the project.
    """

    GNUPG_HOME = os.environ['HOME'] + "/.config/leap/gnupg"
    GNUPG_BINARY = "/usr/bin/gpg"  # this has to be changed based on OS

    def __init__(self, gpgbinary=GNUPG_BINARY, gnupghome=GNUPG_HOME,
                 verbose=False, use_agent=False, keyring=None, options=None):
        super(GPGWrapper, self).__init__(gnupghome=gnupghome,
                                         gpgbinary=gpgbinary,
                                         verbose=verbose,
                                         use_agent=use_agent,
                                         keyring=keyring,
                                         options=options)
        self.result_map['list-packets'] = ListPackets

    def find_key_by_email(self, email, secret=False):
        """
        Find user's key based on their email.
        """
        for key in self.list_keys(secret=secret):
            for uid in key['uids']:
                if re.search(email, uid):
                    return key
        raise LookupError("GnuPG public key for email %s not found!" % email)

    def find_key_by_subkey(self, subkey):
        for key in self.list_keys():
            for sub in key['subkeys']:
                if sub[0] == subkey:
                    return key
        raise LookupError(
            "GnuPG public key for subkey %s not found!" % subkey)

    def find_key_by_keyid(self, keyid):
        for key in self.list_keys():
            if keyid == key['keyid']:
                return key
        raise LookupError(
            "GnuPG public key for subkey %s not found!" % subkey)

    def encrypt(self, data, recipient, sign=None, always_trust=True,
                passphrase=None, symmetric=False):
        """
        Encrypt data using GPG.
        """
        # TODO: devise a way so we don't need to "always trust".
        return super(GPGWrapper, self).encrypt(data, recipient, sign=sign,
                                               always_trust=always_trust,
                                               passphrase=passphrase,
                                               symmetric=symmetric,
                                               cipher_algo='AES256')

    def decrypt(self, data, always_trust=True, passphrase=None):
        """
        Decrypt data using GPG.
        """
        # TODO: devise a way so we don't need to "always trust".
        return super(GPGWrapper, self).decrypt(data,
                                               always_trust=always_trust,
                                               passphrase=passphrase)

    def send_keys(self, keyserver, *keyids):
        """
        Send keys to a keyserver
        """
        result = self.result_map['list'](self)
        gnupg.logger.debug('send_keys: %r', keyids)
        data = gnupg._make_binary_stream("", self.encoding)
        args = ['--keyserver', keyserver, '--send-keys']
        args.extend(keyids)
        self._handle_io(args, data, result, binary=True)
        gnupg.logger.debug('send_keys result: %r', result.__dict__)
        data.close()
        return result

    def encrypt_file(self, file, recipients, sign=None,
                     always_trust=False, passphrase=None,
                     armor=True, output=None, symmetric=False,
                     cipher_algo=None):
        "Encrypt the message read from the file-like object 'file'"
        args = ['--encrypt']
        if symmetric:
            args = ['--symmetric']
            if cipher_algo:
                args.append('--cipher-algo %s' % cipher_algo)
        else:
            args = ['--encrypt']
            if not _is_sequence(recipients):
                recipients = (recipients,)
            for recipient in recipients:
                args.append('--recipient "%s"' % recipient)
        if armor:  # create ascii-armored output - set to False for binary
            args.append('--armor')
        if output:  # write the output to a file with the specified name
            if os.path.exists(output):
                os.remove(output)  # to avoid overwrite confirmation message
            args.append('--output "%s"' % output)
        if sign:
            args.append('--sign --default-key "%s"' % sign)
        if always_trust:
            args.append("--always-trust")
        result = self.result_map['crypt'](self)
        self._handle_io(args, file, result, passphrase=passphrase, binary=True)
        logger.debug('encrypt result: %r', result.data)
        return result

    def list_packets(self, raw_data):
        args = ["--list-packets"]
        result = self.result_map['list-packets'](self)
        self._handle_io(
            args,
            _make_binary_stream(raw_data, self.encoding),
            result,
        )
        return result

    def encrypted_to(self, raw_data):
        """
        Return the key to which raw_data is encrypted to.
        """
        # TODO: make this support multiple keys.
        result = self.list_packets(raw_data)
        if not result.key:
            raise LookupError(
                "Content is not encrypted to a GnuPG key!")
        try:
            return self.find_key_by_keyid(result.key)
        except:
            return self.find_key_by_subkey(result.key)

    def is_encrypted_sym(self, raw_data):
        result = self.list_packets(raw_data)
        return bool(result.need_passphrase_sym)

    def is_encrypted_asym(self, raw_data):
        result = self.list_packets(raw_data)
        return bool(result.key)

    def is_encrypted(self, raw_data):
        self.is_encrypted_asym() or self.is_encrypted_sym()
