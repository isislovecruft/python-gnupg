#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Create a new 8192-bit GnuPG keypair.

:authors: Isis <isis@patternsinthevoid.net> 0xa3adb67a2cdb8b35
:license: MIT license
:copyright: (c) 2013 Isis Agora Lovecruft
"""

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

import os
import logging

import gnupg

from gnupg import _logger

# Set up logging:
log = _logger.create_logger(9)
log.setLevel(9)


#―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
# Settings
#
# You probably want to edit the following variables. Ones which are currently
# set to strings are necessary; the ones which are set to `None` are optional.

# The directory to use as the homedir for GnuPG (it will contain the
# secring.gpg and pubring.gpg, etc.)
NEWKEY_DIR = './8192-bit-key'

# The name you go by, as it should appear in the primary keyid, i.e. "Evey
# Hammond":
NAME = 'Someone'

# The comment which goes in parantheses after the name and before the email
# address on the key's primary uid. Leave as None to not have one.
NAME_COMMENT = None

# The email address for the primary UID (You *should* actually be able to put
# whatever you want here, like a domain or something, because the GnuPG
# `--allow-freeform-uid` option will be used. I've not actually tested this
# though.)
NAME_EMAIL = 'someone@example.com'

# Expiration date for the new key. To use the default expiration of one year,
# set to None.
#EXPIRE_DATE = '1999-09-19'
EXPIRE_DATE = None


# GnuPG-1.4.x allows the automated creation of passphraseless keys. If using
# GnuPG-1.4.x, and you don't specify the passphrase, you can of course set it
# later with `$ gpg --edit-key` and then at the prompt typing `password`. If
# using a GnuPG from the 2.x series, you *must* specify a password here
# (though you can still change it afterward).
PASSPHRASE = None

# Type of key, i.e. 'RSA' or 'DSA' or something else. I've only tested
# 8192-bit keys with RSA.
KEY_TYPE = 'RSA'

# Uses for the key. Can be things like 'cert,sign' or 'cert' or 'cert,auth'.
KEY_USAGE = 'cert'

# Key bitlength. You likely want 8192, if you're using this script.
#
# It *is* possible to create 16834-bit keys, though it requires modifying and
# recompiling GnuPG. Doing this is a bit janky due to internal GnuPG buffers
# in several parts of the codebase being limited to 8192-bits, the key cannot
# be handled by *most* keyservers (there appears to be only one public
# keyserver which supports 16384-bit keys being uploaded to it), and the
# 16834-bit key will likely require the modified GnuPG to work with it (even
# then some operations, such as removal of the primary secret key, but not the
# primary public key, from the keychain will be badly broken).
KEY_LENGTH = 8192

# Type of subkey. None to skip subkey generation. You can add keys later
# through `$ gpg --edit-key`. For compatibility with people who aren't doing
# crazy things with their keys, you maybe probably want to use `--edit-key` to
# create some nice, normal, "overly-paranoid" 4096-bit keys.
SUBKEY_TYPE = 'RSA'

# Same as KEY_USAGE.
#SUBKEY_USAGE = None
SUBKEY_USAGE = 'sign'

# Same as KEY_LENGTH.
#SUBKEY_LENGTH = None
SUBKEY_LENGTH = 4096

# The default keyserver for the key, which is embedded into the key, telling
# other people's GnuPGs to fetch (and send updates) to this URL:
KEYSERVER = None

# Set the cipher, hash, and compression preference values for this key. This
# expects the same type of string as the sub-command ‘setpref’ in the
# --edit-key menu. The default preferences are given in
# ``gnupg.GPG.default_preference_list``.
PREFERENCES = None
#―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――


gpg = gnupg.GPG(homedir=NEWKEY_DIR)
allparams = {'name_real': NAME,
             'name_comment': NAME_COMMENT,
             'name_email': NAME_EMAIL,
             'expire_date': EXPIRE_DATE,
             'passphrase': PASSPHRASE,
             'key_type': KEY_TYPE,
             'key_usage': KEY_USAGE,
             'key_length': KEY_LENGTH,
             'subkey_type': SUBKEY_TYPE,
             'subkey_usage': SUBKEY_USAGE,
             'subkey_length': SUBKEY_LENGTH,
             'keyserver': KEYSERVER,
             'preferences': PREFERENCES}

def createBatchfile(keyparams=allparams):
    """Create the batchfile for our new key.

    :params dict keyparams: A dictionary of arguments for creating the key. It
                            should probably be ``allparams``.
    :rtype: str
    :returns: A string containing the entire GnuPG batchfile.
    """
    useparams = {}
    for key, value in keyparams.items():
        if value:
            useparams.update({key: value})
    batchfile = gpg.gen_key_input(separate_keyring=True,
                                  save_batchfile=True,
                                  **useparams)
    log.info("Generated GnuPG batch file:\n%s" % batchfile)
    return batchfile

def createKey(batchfile):
    """Create a new keypair from a **batchfile**.

    Writes the new keys into keyrings named after ``NAME_EMAIL`` inside the
    ``NEWKEY_DIR``.

    :params str batchfile: A GnuPG batchfile. See :func:`createBatchfile`.
    """
    key = gpg.gen_key(batchfile)
    fingerprint = key.fingerprint

    if not fingerprint:
        log.error("Key creation seems to have failed: %s" % key.status)
        return None, None
    return key, fingerprint

def displayNewKey(key):
    """Use ``gnupg.GPG.list_keys()`` to display details of the new key."""

    if key.keyring:
        gpg.keyring = key.keyring
    if key.secring:
        gpg.secring = key.secring

    # Using '--fingerprint' twice will display subkey fingerprints too:
    gpg.options = ['--fingerprint', '--fingerprint']
    keylist = gpg.list_keys(secret=True)

    # `result` is a `gnupg._parsers.ListKeys`, which is list-like, so iterate
    # over all the keys and display their info:
    for gpgkey in keylist:
        for k, v in gpgkey:
            log.info("%s: %s" % (k.capitalize(), v))

    return keylist

def exportNewKey(fingerprint):
    """Export the new keys into .asc files.

    :param str fingerprint: A full key fingerprint.
    """
    log.info("Exporting key: %s" % fingerprint)

    keyfn = os.path.join(gpg.homedir,
                         fingerprint + '-8192-bit-key') + os.path.extsep

    pubkey = gpg.export_keys(fingerprint)
    seckey = gpg.export_keys(fingerprint, secret=True)
    subkey = gpg.export_keys(fingerprint, secret=True, subkeys=True)

    with open(keyfn + 'pub' + os.path.extsep + 'asc', 'w') as fh:
        fh.write(pubkey)
    with open(keyfn + 'sec' + os.path.extsep + 'asc', 'w') as fh:
        fh.write(seckey)
    with open(keyfn + 'sub' + os.path.extsep + 'asc', 'w') as fh:
        fh.write(subkey)


if __name__ == '__main__':
    if (NAME == 'Someone') or (NAME_EMAIL == 'someone@example.com'):
        log.info("Please edit the settings variables within this script.")
        log.info("Exiting...")
        exit(1)
    else:
        try:
            batchfile = createBatchfile()
            key, fingerprint = createKey(batchfile)
            log.info("New key with fingerprint %r created" % fingerprint)
            displayNewKey(key)
            exportNewKey(fingerprint)

        except Exception as error:
            log.error(error)
