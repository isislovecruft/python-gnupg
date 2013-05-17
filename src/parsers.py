#!/usr/bin/env python
#-*- encoding: utf-8 -*-
#
# This file is part of python-gnupg, a Python wrapper around GnuPG.
# Copyright © 2013 Isis Lovecruft
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
parsers.py
----------
Classes for parsing GnuPG status messages and sanitising commandline options.
'''

__module__ = 'gnupg.parsers'


import logging
import re

from util import logger
import util


ESCAPE_PATTERN = re.compile(r'\\x([0-9a-f][0-9a-f])', re.I)
HEXIDECIMAL    = re.compile('([0-9A-Fa-f]{2})+')


class ProtectedOption(Exception):
    """Raised when the option passed to GPG is disallowed."""

class UsageError(Exception):
    """Raised when incorrect usage of the API occurs.."""


def _check_preferences(prefs, pref_type=None):
    """Check cipher, digest, and compression preference settings.

    MD5 is not allowed. This is not 1994.[0] SHA1 is allowed grudgingly.[1]

    [0]: http://www.cs.colorado.edu/~jrblack/papers/md5e-full.pdf
    [1]: http://eprint.iacr.org/2008/469.pdf
    """
    if prefs is None: return

    cipher   = frozenset(['AES256', 'AES192', 'AES128',
                          'CAMELLIA256', 'CAMELLIA192',
                          'TWOFISH', '3DES'])
    digest   = frozenset(['SHA512', 'SHA384', 'SHA256', 'SHA224', 'RMD160',
                          'SHA1'])
    compress = frozenset(['BZIP2', 'ZLIB', 'ZIP', 'Uncompressed'])
    all      = frozenset([cipher, digest, compress])

    if isinstance(prefs, str):
        prefs = set(prefs.split())
    elif isinstance(prefs, list):
        prefs = set(prefs)
    else:
        msg = "prefs must be a list of strings, or one space-separated string"
        log.error("parsers._check_preferences(): %s" % message)
        raise TypeError(message)

    if not pref_type:
        pref_type = 'all'

    allowed = str()

    if pref_type == 'cipher':
        allowed += ' '.join(prefs.intersection(cipher))
    if pref_type == 'digest':
        allowed += ' '.join(prefs.intersection(digest))
    if pref_type == 'compress':
        allowed += ' '.join(prefs.intersection(compress))
    if pref_type == 'all':
        allowed += ' '.join(prefs.intersection(all))

    return allowed

def _fix_unsafe(shell_input):
    """Find characters used to escape from a string into a shell, and wrap them
    in quotes if they exist. Regex pilfered from python-3.x shlex module.

    :param str shell_input: The input intended for the GnuPG process.
    """
    ## xxx do we want to add ';'?
    _unsafe = re.compile(r'[^\w@%+=:,./-]', 256)
    try:
        if len(_unsafe.findall(shell_input)) == 0:
            return shell_input.strip()
        else:
            clean = "'" + shell_input.replace("'", "'\"'\"'") + "'"
            return clean
    except TypeError:
        return None

def _hyphenate(input, add_prefix=False):
    """Change underscores to hyphens so that object attributes can be easily
    tranlated to GPG option names.

    :param str input: The attribute to hyphenate.
    :param bool add_prefix: If True, add leading hyphens to the input.
    :rtype: str
    :return: The ``input`` with underscores changed to hyphens.
    """
    ret  = '--' if add_prefix else ''
    ret += input.replace('_', '-')
    return ret

def _is_allowed(input):
    """
    Check that an option or argument given to GPG is in the set of allowed
    options, the latter being a strict subset of the set of all options known
    to GPG.

    :param str input: An input meant to be parsed as an option or flag to the
                      GnuPG process. Should be formatted the same as an option
                      or flag to the commandline gpg, i.e. "--encrypt-files".
    :ivar frozenset _possible: All known GPG options and flags.
    :ivar frozenset _allowed: All allowed GPG options and flags, e.g. all GPG
                              options and flags which we are willing to
                              acknowledge and parse. If we want to support a
                              new option, it will need to have its own parsing
                              class and its name will need to be added to this
                              set.

    :rtype: Exception or str
    :raise: :exc:UsageError if ``_allowed`` is not a subset of ``_possible``.
            ProtectedOption if ``input`` is not in the set ``_allowed``.
    :return: The original parameter ``input``, unmodified and unsanitized,
             if no errors occur.
    """

    _all = ("""
--allow-freeform-uid              --multifile
--allow-multiple-messages         --no
--allow-multisig-verification     --no-allow-freeform-uid
--allow-non-selfsigned-uid        --no-allow-multiple-messages
--allow-secret-key-import         --no-allow-non-selfsigned-uid
--always-trust                    --no-armor
--armor                           --no-armour
--armour                          --no-ask-cert-expire
--ask-cert-expire                 --no-ask-cert-level
--ask-cert-level                  --no-ask-sig-expire
--ask-sig-expire                  --no-auto-check-trustdb
--attribute-fd                    --no-auto-key-locate
--attribute-file                  --no-auto-key-retrieve
--auto-check-trustdb              --no-batch
--auto-key-locate                 --no-comments
--auto-key-retrieve               --no-default-keyring
--batch                           --no-default-recipient
--bzip2-compress-level            --no-disable-mdc
--bzip2-decompress-lowmem         --no-emit-version
--card-edit                       --no-encrypt-to
--card-status                     --no-escape-from-lines
--cert-digest-algo                --no-expensive-trust-checks
--cert-notation                   --no-expert
--cert-policy-url                 --no-force-mdc
--change-pin                      --no-force-v3-sigs
--charset                         --no-force-v4-certs
--check-sig                       --no-for-your-eyes-only
--check-sigs                      --no-greeting
--check-trustdb                   --no-groups
--cipher-algo                     --no-literal
--clearsign                       --no-mangle-dos-filenames
--command-fd                      --no-mdc-warning
--command-file                    --no-options
--comment                         --no-permission-warning
--completes-needed                --no-pgp2
--compress-algo                   --no-pgp6
--compression-algo                --no-pgp7
--compress-keys                   --no-pgp8
--compress-level                  --no-random-seed-file
--compress-sigs                   --no-require-backsigs
--ctapi-driver                    --no-require-cross-certification
--dearmor                         --no-require-secmem
--dearmour                        --no-rfc2440-text
--debug                           --no-secmem-warning
--debug-all                       --no-show-notation
--debug-ccid-driver               --no-show-photos
--debug-level                     --no-show-policy-url
--decrypt                         --no-sig-cache
--decrypt-files                   --no-sig-create-check
--default-cert-check-level        --no-sk-comments
--default-cert-expire             --no-strict
--default-cert-level              --notation-data
--default-comment                 --not-dash-escaped
--default-key                     --no-textmode
--default-keyserver-url           --no-throw-keyid
--default-preference-list         --no-throw-keyids
--default-recipient               --no-tty
--default-recipient-self          --no-use-agent
--default-sig-expire              --no-use-embedded-filename
--delete-keys                     --no-utf8-strings
--delete-secret-and-public-keys   --no-verbose
--delete-secret-keys              --no-version
--desig-revoke                    --openpgp
--detach-sign                     --options
--digest-algo                     --output
--disable-ccid                    --override-session-key
--disable-cipher-algo             --passphrase
--disable-dsa2                    --passphrase-fd
--disable-mdc                     --passphrase-file
--disable-pubkey-algo             --passphrase-repeat
--display                         --pcsc-driver
--display-charset                 --personal-cipher-preferences
--dry-run                         --personal-cipher-prefs
--dump-options                    --personal-compress-preferences
--edit-key                        --personal-compress-prefs
--emit-version                    --personal-digest-preferences
--enable-dsa2                     --personal-digest-prefs
--enable-progress-filter          --pgp2
--enable-special-filenames        --pgp6
--enarmor                         --pgp7
--enarmour                        --pgp8
--encrypt                         --photo-viewer
--encrypt-files                   --pipemode
--encrypt-to                      --preserve-permissions
--escape-from-lines               --primary-keyring
--exec-path                       --print-md
--exit-on-status-write-error      --print-mds
--expert                          --quick-random
--export                          --quiet
--export-options                  --reader-port
--export-ownertrust               --rebuild-keydb-caches
--export-secret-keys              --recipient
--export-secret-subkeys           --recv-keys
--fast-import                     --refresh-keys
--fast-list-mode                  --remote-user
--fetch-keys                      --require-backsigs
--fingerprint                     --require-cross-certification
--fixed-list-mode                 --require-secmem
--fix-trustdb                     --rfc1991
--force-mdc                       --rfc2440
--force-ownertrust                --rfc2440-text
--force-v3-sigs                   --rfc4880
--force-v4-certs                  --run-as-shm-coprocess
--for-your-eyes-only              --s2k-cipher-algo
--gen-key                         --s2k-count
--gen-prime                       --s2k-digest-algo
--gen-random                      --s2k-mode
--gen-revoke                      --search-keys
--gnupg                           --secret-keyring
--gpg-agent-info                  --send-keys
--gpgconf-list                    --set-filename
--gpgconf-test                    --set-filesize
--group                           --set-notation
--help                            --set-policy-url
--hidden-encrypt-to               --show-keyring
--hidden-recipient                --show-notation
--homedir                         --show-photos
--honor-http-proxy                --show-policy-url
--ignore-crc-error                --show-session-key
--ignore-mdc-error                --sig-keyserver-url
--ignore-time-conflict            --sign
--ignore-valid-from               --sign-key
--import                          --sig-notation
--import-options                  --sign-with
--import-ownertrust               --sig-policy-url
--interactive                     --simple-sk-checksum
--keyid-format                    --sk-comments
--keyring                         --skip-verify
--keyserver                       --status-fd
--keyserver-options               --status-file
--lc-ctype                        --store
--lc-messages                     --strict
--limit-card-insert-tries         --symmetric
--list-config                     --temp-directory
--list-key                        --textmode
--list-keys                       --throw-keyid
--list-only                       --throw-keyids
--list-options                    --trustdb-name
--list-ownertrust                 --trusted-key
--list-packets                    --trust-model
--list-public-keys                --try-all-secrets
--list-secret-keys                --ttyname
--list-sig                        --ttytype
--list-sigs                       --ungroup
--list-trustdb                    --update-trustdb
--load-extension                  --use-agent
--local-user                      --use-embedded-filename
--lock-multiple                   --user
--lock-never                      --utf8-strings
--lock-once                       --verbose
--logger-fd                       --verify
--logger-file                     --verify-files
--lsign-key                       --verify-options
--mangle-dos-filenames            --version
--marginals-needed                --warranty
--max-cert-depth                  --with-colons
--max-output                      --with-fingerprint
--merge-only                      --with-key-data
--min-cert-level                  --yes
""").split()

    _possible = frozenset(_all)

    ## these are the allowed options we will handle so far, all others should
    ## be dropped. this dance is so that when new options are added later, we
    ## merely add the to the _allowed list, and the `` _allowed.issubset``
    ## assertion will check that GPG will recognise them
    ##
    ## xxx checkout the --store option for creating rfc1991 data packets
    ## xxx key fetching/retrieving options: [fetch_keys, merge_only, recv_keys]
    ##
    _allowed = frozenset(
        ['--list-keys', '--list-key', '--fixed-list-mode',
         '--list-secret-keys', '--list-public-keys',
         '--list-packets',  '--with-colons',
         '--list-options',
         '--delete-keys', '--delete-secret-keys',
         '--encrypt', '--encrypt-files',
         '--decrypt', '--decrypt-files',
         '--always-trust',
         '--symmetric',
         '--use-agent', '--no-use-agent',
         '--print-mds', '--print-md',
         '--sign', '--clearsign', '--detach-sign',
         '--armor', '--armour',
         '--gen-key', '--batch',
         '--decrypt', '--decrypt-files', '--multifile', '--output',
         '--cert-digest-algo', '--digest-algo',
         '--cipher-algo', '--compress-algo', '--personal-digest-prefs',
         '--personal-cipher-prefs', '--personal-compress-prefs',
         '--import',
         '--export', '--export-secret-keys', '--export-secret-subkeys',
         '--verify',
         '--version', '--no-emit-version', '--output',
         '--status-fd', '--no-tty', '--passphrase-fd',
         '--homedir', '--no-default-keyring', '--default-key',
         '--keyring', '--secret-keyring', '--primary-keyring',
         '--fingerprint',])

    ## check that _allowed is a subset of _possible
    try:
        assert _allowed.issubset(_possible), \
            '_allowed is not subset of known options, difference: %s' \
            % _allowed.difference(_possible)
    except AssertionError as ae:
        logger.debug("_is_allowed(): %s" % ae.message)
        raise UsageError(ae.message)

    ## if we got a list of args, join them
    if not isinstance(input, str):
        input = ' '.join([x for x in input])

    if isinstance(input, str):
        if input.find('_') > 0:
            if not input.startswith('--'):
                hyphenated = _hyphenate(input, add_prefix=True)
            else:
                hyphenated = _hyphenate(input)
        else:
            hyphenated = input
            try:
                assert hyphenated in _allowed
            except AssertionError as ae:
                logger.warn("_is_allowed(): Dropping option '%s'..."
                            % _fix_unsafe(hyphenated))
                raise ProtectedOption("Option '%s' not supported."
                                      % _fix_unsafe(hyphenated))
            else:
                return input
    return None

def _is_hex(string):
    """Check that a string is hexidecimal, with alphabetic characters
    capitalized and without whitespace.

    :param str string: The string to check.
    """
    matched = HEXIDECIMAL.match(string)
    if matched is not None and len(matched.group()) >= 2:
        return True
    return False

def _sanitise(*args):
    """Take an arg or the key portion of a kwarg and check that it is in the
    set of allowed GPG options and flags, and that it has the correct
    type. Then, attempt to escape any unsafe characters. If an option is not
    allowed, drop it with a logged warning. Returns a dictionary of all
    sanitised, allowed options.

    Each new option that we support that is not a boolean, but instead has
    some extra inputs, i.e. "--encrypt-file foo.txt", will need some basic
    safety checks added here.

    GnuPG has three-hundred and eighteen commandline flags. Also, not all
    implementations of OpenPGP parse PGP packets and headers in the same way,
    so there is added potential there for messing with calls to GPG.

    For information on the PGP message format specification, see:
        https://www.ietf.org/rfc/rfc1991.txt

    If you're asking, "Is this *really* necessary?": No. Not really. See:
        https://xkcd.com/1181/

    :param str args: (optional) The boolean arguments which will be passed to
                     the GnuPG process.
    :rtype: str
    :returns: ``sanitised``
    """

    def _check_option(arg, value):
        """
        Check that a single :param:arg is an allowed option. If it is allowed,
        quote out any escape characters in :param:values, and add the pair to
        :ivar:sanitised.

        :param str arg: The arguments which will be passed to the GnuPG
                        process, and, optionally their corresponding values.
                        The values are any additional arguments following the
                        GnuPG option or flag. For example, if we wanted to pass
                        "--encrypt --recipient isis@leap.se" to gpg, then
                        "--encrypt" would be an arg without a value, and
                        "--recipient" would also be an arg, with a value of
                        "isis@leap.se".
        :ivar list checked: The sanitised, allowed options and values.
        :rtype: str
        :returns: A string of the items in ``checked`` delimited by spaces.
        """
        safe_option = str()
        try:
            flag = _is_allowed(arg)
            assert flag is not None, "_check_option(): got None for flag"
        except (AssertionError, ProtectedOption) as error:
            logger.warn("_check_option(): %s" % error.message)
        else:
            safe_option += (flag + " ")
            if isinstance(value, str):
                values = value.split(' ')
                for v in values:
                    val = _fix_unsafe(v)
                    if val is not None and val.strip() != "":
                        if flag in ['--encrypt', '--encrypt-files', '--decrypt',
                                    '--decrypt-files', '--import', '--verify']:
                            ## Place checks here:
                            if util._is_file(val):
                                safe_option += (val + " ")
                            else:
                                logger.debug("_check_option(): %s not file: %s"
                                             % (flag, val))
                        elif flag in ['--default-key', '--recipient',
                                      '--export', '--export-secret-keys',
                                      '--delete-keys',
                                      '--export-secret-subkeys',]:
                            if _is_hex(val):
                                safe_option += (val + " ")
                            else:
                                logger.debug("_check_option(): '%s %s' not hex."
                                             % (flag, val))
                        else:
                            safe_option += (val + " ")
                            logger.debug("_check_option(): No checks for %s"
                                         % val)
        return safe_option

    is_flag = lambda x: x.startswith('--')

    def _make_filo(args_string):
        filo = arg.split(' ')
        filo.reverse()
        logger.debug("_make_filo(): Converted to reverse list: %s" % filo)
        return filo

    def _make_groups(filo):
        groups = {}
        while len(filo) >= 1:
            last = filo.pop()
            if is_flag(last):
                logger.debug("_make_groups(): Got arg: %s" % last)
                if last == '--verify':
                    groups[last] = str(filo.pop())
                    ## accept the read-from-stdin arg:
                    if len(filo) >= 1 and filo[len(filo)-1] == '-':
                        groups[last] += str(' - \'\'') ## gross hack
                else:
                    groups[last] = str()
                while len(filo) > 1 and not is_flag(filo[len(filo)-1]):
                    logger.debug("_make_groups(): Got value: %s"
                                 % filo[len(filo)-1])
                    groups[last] += (filo.pop() + " ")
                else:
                    if len(filo) == 1 and not is_flag(filo[0]):
                        logger.debug("_make_groups(): Got value: %s" % filo[0])
                        groups[last] += filo.pop()
            else:
                logger.debug("_make_groups(): Got solitary value: %s" % last)
                groups["xxx"] = last
        return groups

    def _check_groups(groups):
        logger.debug("_check_groups(): Got groups: %s" % groups)
        checked_groups = []
        for a,v in groups.items():
            v = None if len(v) == 0 else v
            safe = _check_option(a, v)
            if safe is not None and not safe.strip() == "":
                logger.debug("_check_groups(): appending option: %s" % safe)
                checked_groups.append(safe)
            else:
                logger.debug("_check_groups(): dropped option '%s %s'" % (a,v))
        return checked_groups

    if args is not None:
        option_groups = {}
        for arg in args:
            ## if we're given a string with a bunch of options in it split them
            ## up and deal with them separately
            if isinstance(arg, str):
                logger.debug("_sanitise(): Got arg string: %s" % arg)
                if arg.find(' ') > 0:
                    filo = _make_filo(arg)
                    option_groups.update(_make_groups(filo))
                else:
                    option_groups.update({ arg: "" })
            elif isinstance(arg, list):
                logger.debug("_sanitise(): Got arg list: %s" % arg)
                arg.reverse()
                option_groups.update(_make_groups(arg))
            else:
                logger.debug("_sanitise(): Got non str or list arg: %s" % arg)
        checked = _check_groups(option_groups)
        sanitised = ' '.join(x for x in checked)
        return sanitised
    else:
        logger.debug("_sanitise(): Got None for args")

def _sanitise_list(arg_list):
    """A generator for iterating through a list of gpg options and sanitising
    them.

    :param list arg_list: A list of options and flags for GnuPG.
    :rtype: generator
    :return: A generator whose next() method returns each of the items in
             ``arg_list`` after calling ``_sanitise()`` with that item as a
             parameter.
    """
    if isinstance(arg_list, list):
        for arg in arg_list:
            safe_arg = _sanitise(arg)
            if safe_arg != "":
                yield safe_arg


class Verify(object):
    """Parser for internal status messages from GnuPG for ``--verify``.
    """

    TRUST_UNDEFINED = 0
    TRUST_NEVER = 1
    TRUST_MARGINAL = 2
    TRUST_FULLY = 3
    TRUST_ULTIMATE = 4

    TRUST_LEVELS = { "TRUST_UNDEFINED" : TRUST_UNDEFINED,
                     "TRUST_NEVER" : TRUST_NEVER,
                     "TRUST_MARGINAL" : TRUST_MARGINAL,
                     "TRUST_FULLY" : TRUST_FULLY,
                     "TRUST_ULTIMATE" : TRUST_ULTIMATE, }

    #: True if the signature is valid, False otherwise.
    valid = False
    #: A string describing the status of the signature verification.
    #: Can be one of ``'signature bad'``, ``'signature good'``,
    #: ``'signature valid'``, ``'signature error'``, ``'decryption failed'``,
    #: ``'no public key'``, ``'key exp'``, or ``'key rev'``.
    status = None
    #: The fingerprint of the signing keyid.
    fingerprint = None
    #: The fingerprint of the corresponding public key, which may be different
    #: if the signature was created with a subkey.
    pubkey_fingerprint = None
    #: The keyid of the signing key.
    key_id = None
    #: The id of the signature itself.
    signature_id = None
    #: The creation date of the signing key.
    creation_date = None
    #: The timestamp of the purported signature, if we are unable to parse it.
    timestamp = None
    #: The userid of the signing key which was used to create the signature.
    username = None
    #: When the signing key is due to expire.
    expire_timestamp = None
    #: The timestamp for when the signature was created.
    sig_timestamp = None
    #: A number 0-4 describing the trust level of the signature.
    trust_level = None
    #: The string corresponding to the ``trust_level`` number.
    trust_text = None

    def __init__(self, gpg):
        self.gpg = gpg

    def __nonzero__(self):
        return self.valid
    __bool__ = __nonzero__

    def _handle_status(self, key, value):
        if key in self.TRUST_LEVELS:
            self.trust_text = key
            self.trust_level = self.TRUST_LEVELS[key]
        elif key in ("RSA_OR_IDEA", "NODATA", "IMPORT_RES", "PLAINTEXT",
                     "PLAINTEXT_LENGTH", "POLICY_URL", "DECRYPTION_INFO",
                     "DECRYPTION_OKAY", "INV_SGNR"):
            pass
        elif key == "BADSIG":
            self.valid = False
            self.status = 'signature bad'
            self.key_id, self.username = value.split(None, 1)
        elif key == "GOODSIG":
            self.valid = True
            self.status = 'signature good'
            self.key_id, self.username = value.split(None, 1)
        elif key == "VALIDSIG":
            (self.fingerprint,
             self.creation_date,
             self.sig_timestamp,
             self.expire_timestamp) = value.split()[:4]
            self.pubkey_fingerprint = value.split()[-1]
            self.status = 'signature valid'
        elif key == "SIG_ID":
            (self.signature_id,
             self.creation_date, self.timestamp) = value.split()
        elif key == "ERRSIG":
            self.valid = False
            (self.key_id,
             algo, hash_algo,
             cls,
             self.timestamp) = value.split()[:5]
            self.status = 'signature error'
        elif key == "DECRYPTION_FAILED":
            self.valid = False
            self.key_id = value
            self.status = 'decryption failed'
        elif key == "NO_PUBKEY":
            self.valid = False
            self.key_id = value
            self.status = 'no public key'
        elif key in ("KEYEXPIRED", "SIGEXPIRED"):
            # these are useless in verify, since they are spit out for any
            # pub/subkeys on the key, not just the one doing the signing.
            # if we want to check for signatures with expired key,
            # the relevant flag is EXPKEYSIG.
            pass
        elif key in ("EXPKEYSIG", "REVKEYSIG"):
            # signed with expired or revoked key
            self.valid = False
            self.key_id = value.split()[0]
            self.status = (('%s %s') % (key[:3], key[3:])).lower()
        else:
            raise ValueError("Unknown status message: %r" % key)


class Crypt(Verify):
    """Parser for internal status messages from GnuPG for
    ``--encrypt````--decrypt``, and ``--decrypt-files``.
    """
    def __init__(self, gpg):
        self.gpg = gpg
        self.data = str()
        self.ok = False
        self.status = str()

    def __nonzero__(self):
        if self.ok: return True
        return False

    __bool__ = __nonzero__

    def __str__(self):
        return self.data.decode(self.gpg.encoding, self.gpg._decode_errors)

    def __repr__(self):
        return str(self)

    def _handle_status(self, key, value):
        """Parse a status code from the attached GnuPG process.

        :raises: :exc:`ValueError` if the status message is unknown.
        """
        if key in ("ENC_TO", "USERID_HINT", "GOODMDC", "END_DECRYPTION",
                   "BEGIN_SIGNING", "NO_SECKEY", "ERROR", "NODATA",
                   "CARDCTRL"):
            # in the case of ERROR, this is because a more specific error
            # message will have come first
            pass
        elif key in ("NEED_PASSPHRASE", "BAD_PASSPHRASE", "GOOD_PASSPHRASE",
                     "MISSING_PASSPHRASE", "DECRYPTION_FAILED",
                     "KEY_NOT_CREATED"):
            self.status = key.replace("_", " ").lower()
        elif key == "NEED_PASSPHRASE_SYM":
            self.status = 'need symmetric passphrase'
        elif key == "BEGIN_DECRYPTION":
            self.status = 'decryption incomplete'
        elif key == "BEGIN_ENCRYPTION":
            self.status = 'encryption incomplete'
        elif key == "DECRYPTION_OKAY":
            self.status = 'decryption ok'
            self.ok = True
        elif key == "END_ENCRYPTION":
            self.status = 'encryption ok'
            self.ok = True
        elif key == "INV_RECP":
            self.status = 'invalid recipient'
        elif key == "KEYEXPIRED":
            self.status = 'key expired'
        elif key == "SIG_CREATED":
            self.status = 'sig created'
        elif key == "SIGEXPIRED":
            self.status = 'sig expired'
        else:
            Verify._handle_status(self, key, value)

class GenKey(object):
    """Handle status messages for --gen-key"""
    def __init__(self, gpg):
        self.gpg = gpg
        self.type = None
        self.fingerprint = None

    def __nonzero__(self):
        if self.fingerprint: return True
        return False

    __bool__ = __nonzero__

    def __str__(self):
        return self.fingerprint or ''

    def _handle_status(self, key, value):
        """Parse a status code from the attached GnuPG process.

        :raises: :exc:`ValueError` if the status message is unknown.
        """
        if key in ("PROGRESS", "GOOD_PASSPHRASE", "NODATA", "KEY_NOT_CREATED"):
            pass
        elif key == "KEY_CREATED":
            (self.type, self.fingerprint) = value.split()
        else:
            raise ValueError("Unknown status message: %r" % key)

class DeleteResult(object):
    """Handle status messages for --delete-keys and --delete-secret-keys"""
    def __init__(self, gpg):
        self.gpg = gpg
        self.status = 'ok'

    def __str__(self):
        return self.status

    problem_reason = { '1': 'No such key',
                       '2': 'Must delete secret key first',
                       '3': 'Ambigious specification', }

    def _handle_status(self, key, value):
        """Parse a status code from the attached GnuPG process.

        :raises: :exc:`ValueError` if the status message is unknown.
        """
        if key == "DELETE_PROBLEM":
            self.status = self.problem_reason.get(value, "Unknown error: %r"
                                                  % value)
        else:
            raise ValueError("Unknown status message: %r" % key)

class Sign(object):
    """Parse GnuPG status messages for signing operations.

    :param gpg: An instance of :class:`gnupg.GPG`.
    """

    #: The type of signature created.
    sig_type = None
    #: The algorithm used to create the signature.
    sig_algo = None
    #: The hash algorithm used to create the signature.
    sig_hash_also = None
    #: The fingerprint of the signing keyid.
    fingerprint = None
    #: The timestamp on the signature.
    timestamp = None
    #: xxx fill me in
    what = None

    def __init__(self, gpg):
        self.gpg = gpg

    def __nonzero__(self):
        """Override the determination for truthfulness evaluation.

        :rtype: bool
        :returns: True if we have a valid signature, False otherwise.
        """
        return self.fingerprint is not None
    __bool__ = __nonzero__

    def __str__(self):
        return self.data.decode(self.gpg.encoding, self.gpg._decode_errors)

    def _handle_status(self, key, value):
        """Parse a status code from the attached GnuPG process.

        :raises: :exc:`ValueError` if the status message is unknown.
        """
        if key in ("USERID_HINT", "NEED_PASSPHRASE", "BAD_PASSPHRASE",
                   "GOOD_PASSPHRASE", "BEGIN_SIGNING", "CARDCTRL",
                   "INV_SGNR", "NODATA"):
            pass
        elif key == "SIG_CREATED":
            (self.sig_type, self.sig_algo, self.sig_hash_algo,
             self.what, self.timestamp, self.fingerprint) = value.split()
        else:
            raise ValueError("Unknown status message: %r" % key)

class ListKeys(list):
    """Handle status messages for --list-keys.

        Handle pub and uid (relating the latter to the former).

        Don't care about (info from src/DETAILS):

        crt = X.509 certificate
        crs = X.509 certificate and private key available
        ssb = secret subkey (secondary key)
        uat = user attribute (same as user id except for field 10).
        sig = signature
        rev = revocation signature
        pkd = public key data (special field format, see below)
        grp = reserved for gpgsm
        rvk = revocation key
    """

    def __init__(self, gpg):
        super(ListKeys, self).__init__()
        self.gpg = gpg
        self.curkey = None
        self.fingerprints = []
        self.uids = []

    def key(self, args):
        vars = ("""
            type trust length algo keyid date expires dummy ownertrust uid
        """).split()
        self.curkey = {}
        for i in range(len(vars)):
            self.curkey[vars[i]] = args[i]
        self.curkey['uids'] = []
        if self.curkey['uid']:
            self.curkey['uids'].append(self.curkey['uid'])
        del self.curkey['uid']
        self.curkey['subkeys'] = []
        self.append(self.curkey)

    pub = sec = key

    def fpr(self, args):
        self.curkey['fingerprint'] = args[9]
        self.fingerprints.append(args[9])

    def uid(self, args):
        uid = args[9]
        uid = ESCAPE_PATTERN.sub(lambda m: chr(int(m.group(1), 16)), uid)
        self.curkey['uids'].append(uid)
        self.uids.append(uid)

    def sub(self, args):
        subkey = [args[4], args[11]]
        self.curkey['subkeys'].append(subkey)

    def _handle_status(self, key, value):
        pass


class ImportResult(object):
    """Parse GnuPG status messages for key import operations.

    :type gpg: :class:`gnupg.GPG`
    :param gpg: An instance of :class:`gnupg.GPG`.
    """

    counts = '''count no_user_id imported imported_rsa unchanged
            n_uids n_subk n_sigs n_revoc sec_read sec_imported
            sec_dups not_imported'''.split()

    #: List of all keys imported.
    imported = list()

    #: A list of strings containing the fingerprints of the GnuPG keyIDs
    #: imported.
    fingerprints = list()

    #: A list containing dictionaries with information gathered on keys
    #: imported.
    results = list()

    def __init__(self, gpg):
        self.gpg = gpg
        for result in self.counts:
            setattr(self, result, None)

    def __nonzero__(self):
        """Override the determination for truthfulness evaluation.

        :rtype: bool
        :returns: True if we have immport some keys, False otherwise.
        """
        if self.not_imported: return False
        if not self.fingerprints: return False
        return True
    __bool__ = __nonzero__

    ok_reason = {'0': 'Not actually changed',
                 '1': 'Entirely new key',
                 '2': 'New user IDs',
                 '4': 'New signatures',
                 '8': 'New subkeys',
                 '16': 'Contains private key',}

    problem_reason = { '0': 'No specific reason given',
                       '1': 'Invalid Certificate',
                       '2': 'Issuer Certificate missing',
                       '3': 'Certificate Chain too long',
                       '4': 'Error storing certificate', }

    def _handle_status(self, key, value):
        """Parse a status code from the attached GnuPG process.

        :raises: :exc:`ValueError` if the status message is unknown.
        """
        if key == "IMPORTED":
            # this duplicates info we already see in import_ok & import_problem
            pass
        elif key == "NODATA":
            self.results.append({'fingerprint': None,
                'problem': '0', 'text': 'No valid data found'})
        elif key == "IMPORT_OK":
            reason, fingerprint = value.split()
            reasons = []
            for code, text in list(self.ok_reason.items()):
                if int(reason) | int(code) == int(reason):
                    reasons.append(text)
            reasontext = '\n'.join(reasons) + "\n"
            self.results.append({'fingerprint': fingerprint,
                'ok': reason, 'text': reasontext})
            self.fingerprints.append(fingerprint)
        elif key == "IMPORT_PROBLEM":
            try:
                reason, fingerprint = value.split()
            except:
                reason = value
                fingerprint = '<unknown>'
            self.results.append({'fingerprint': fingerprint,
                'problem': reason, 'text': self.problem_reason[reason]})
        elif key == "IMPORT_RES":
            import_res = value.split()
            for i in range(len(self.counts)):
                setattr(self, self.counts[i], int(import_res[i]))
        elif key == "KEYEXPIRED":
            self.results.append({'fingerprint': None,
                'problem': '0', 'text': 'Key expired'})
        elif key == "SIGEXPIRED":
            self.results.append({'fingerprint': None,
                'problem': '0', 'text': 'Signature expired'})
        else:
            raise ValueError("Unknown status message: %r" % key)

    def summary(self):
        l = []
        l.append('%d imported' % self.imported)
        if self.not_imported:
            l.append('%d not imported' % self.not_imported)
        return ', '.join(l)


class Verify(object):
    """Classes for parsing GnuPG status messages for signature verification.

    :type gpg: :class:`gnupg.GPG`
    :param gpg: An instance of :class:`gnupg.GPG`.
    :attr bool valid: True if the signature or file was verified successfully,
                      False otherwise.
    :attr str fingerprint: The fingerprint of the GnuPG keyID which created the
                           signature.

    :attr str creation_date: The date the signature was made.
    :attr str timestamp: The timestamp used internally in the signature.
    :attr str signature_id: The uid of the signing GnuPG key.
    :attr str status: The internal status message from the GnuPG process.
    """
    ## xxx finish documentation

    TRUST_UNDEFINED = 0
    TRUST_NEVER = 1
    TRUST_MARGINAL = 2
    TRUST_FULLY = 3
    TRUST_ULTIMATE = 4

    TRUST_LEVELS = {"TRUST_UNDEFINED" : TRUST_UNDEFINED,
                    "TRUST_NEVER" : TRUST_NEVER,
                    "TRUST_MARGINAL" : TRUST_MARGINAL,
                    "TRUST_FULLY" : TRUST_FULLY,
                    "TRUST_ULTIMATE" : TRUST_ULTIMATE,}

    def __init__(self, gpg):
        self.gpg = gpg
        self.valid = False
        self.fingerprint = self.creation_date = self.timestamp = None
        self.signature_id = self.key_id = None
        self.username = None
        self.status = None
        self.pubkey_fingerprint = None
        self.expire_timestamp = None
        self.sig_timestamp = None
        self.trust_text = None
        self.trust_level = None

    def __nonzero__(self):
        """Override the determination for truthfulness evaluation.

        :rtype: bool
        :returns: True if we have a valid signature, False otherwise.
        """
        return self.valid
    __bool__ = __nonzero__

    def _handle_status(self, key, value):
        """Parse a status code from the attached GnuPG process.

        :raises: :exc:`ValueError` if the status message is unknown.
        """
        if key in self.TRUST_LEVELS:
            self.trust_text = key
            self.trust_level = self.TRUST_LEVELS[key]
        elif key in ("RSA_OR_IDEA", "NODATA", "IMPORT_RES", "PLAINTEXT",
                     "PLAINTEXT_LENGTH", "POLICY_URL", "DECRYPTION_INFO",
                     "DECRYPTION_OKAY", "INV_SGNR"):
            pass
        elif key == "BADSIG":
            self.valid = False
            self.status = 'signature bad'
            self.key_id, self.username = value.split(None, 1)
        elif key == "GOODSIG":
            self.valid = True
            self.status = 'signature good'
            self.key_id, self.username = value.split(None, 1)
        elif key == "VALIDSIG":
            (self.fingerprint,
             self.creation_date,
             self.sig_timestamp,
             self.expire_timestamp) = value.split()[:4]
            # may be different if signature is made with a subkey
            self.pubkey_fingerprint = value.split()[-1]
            self.status = 'signature valid'
        elif key == "SIG_ID":
            (self.signature_id,
             self.creation_date, self.timestamp) = value.split()
        elif key == "ERRSIG":
            self.valid = False
            (self.key_id,
             algo, hash_algo,
             cls,
             self.timestamp) = value.split()[:5]
            self.status = 'signature error'
        elif key == "DECRYPTION_FAILED":
            self.valid = False
            self.key_id = value
            self.status = 'decryption failed'
        elif key == "NO_PUBKEY":
            self.valid = False
            self.key_id = value
            self.status = 'no public key'
        elif key in ("KEYEXPIRED", "SIGEXPIRED"):
            # these are useless in verify, since they are spit out for any
            # pub/subkeys on the key, not just the one doing the signing.
            # if we want to check for signatures with expired key,
            # the relevant flag is EXPKEYSIG.
            pass
        elif key in ("EXPKEYSIG", "REVKEYSIG"):
            # signed with expired or revoked key
            self.valid = False
            self.key_id = value.split()[0]
            self.status = (('%s %s') % (key[:3], key[3:])).lower()
        else:
            raise ValueError("Unknown status message: %r" % key)

class ListPackets(object):
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

    def _handle_status(self, key, value):
        """Parse a status code from the attached GnuPG process.

        :raises: :exc:`ValueError` if the status message is unknown.
        """
        # TODO: write tests for _handle_status
        if key == 'NODATA':
            self.nodata = True
        elif key == 'ENC_TO':
            # This will only capture keys in our keyring. In the future we
            # may want to include multiple unknown keys in this list.
            self.key, _, _ = value.split()
        elif key == 'NEED_PASSPHRASE':
            self.need_passphrase = True
        elif key == 'NEED_PASSPHRASE_SYM':
            self.need_passphrase_sym = True
        elif key == 'USERID_HINT':
            self.userid_hint = value.strip().split()
        else:
            raise ValueError("Unknown status message: %r" % key)
