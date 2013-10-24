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

'''parsers.py
-------------
Classes for parsing GnuPG status messages and sanitising commandline options.
'''

from __future__ import absolute_import
from __future__ import print_function

import collections
import re

from .      import _util
from ._util import log


ESCAPE_PATTERN = re.compile(r'\\x([0-9a-f][0-9a-f])', re.I)
HEXIDECIMAL    = re.compile('([0-9A-Fa-f]{2})+')


class ProtectedOption(Exception):
    """Raised when the option passed to GPG is disallowed."""

class UsageError(Exception):
    """Raised when incorrect usage of the API occurs.."""


def _check_keyserver(location):
    """Check that a given keyserver is a known protocol and does not contain
    shell escape characters.

    :param str location: A string containing the default keyserver. This
                         should contain the desired keyserver protocol which
                         is supported by the keyserver, for example, the
                         default is ``'hkp://subkeys.pgp.net'``.
    :rtype: str or None
    :returns: A string specifying the protocol and keyserver hostname, if the
              checks passed. If not, returns None.
    """
    protocols = ['hkp://', 'hkps://', 'http://', 'https://', 'ldap://',
                 'mailto:'] ## xxx feels like i´m forgetting one...
    for proto in protocols:
        if location.startswith(proto):
            url = location.replace(proto, str())
            host, slash, extra = url.partition('/')
            if extra: log.warn("URI text for %s: '%s'" % (host, extra))
            log.debug("Got host string for keyserver setting: '%s'" % host)

            host = _fix_unsafe(host)
            if host:
                log.debug("Cleaned host string: '%s'" % host)
                keyserver = proto + host
                return keyserver
            return None

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
        msg = "prefs must be list of strings, or space-separated string"
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
    """Check that an option or argument given to GPG is in the set of allowed
    options, the latter being a strict subset of the set of all options known
    to GPG.

    :param str input: An input meant to be parsed as an option or flag to the
                      GnuPG process. Should be formatted the same as an option
                      or flag to the commandline gpg, i.e. "--encrypt-files".

    :ivar frozenset gnupg_options: All known GPG options and flags.

    :ivar frozenset allowed: All allowed GPG options and flags, e.g. all GPG
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
    gnupg_options = _get_all_gnupg_options()
    allowed = _get_options_group("allowed")

    ## these are the allowed options we will handle so far, all others should
    ## be dropped. this dance is so that when new options are added later, we
    ## merely add the to the _allowed list, and the `` _allowed.issubset``
    ## assertion will check that GPG will recognise them
    try:
        ## check that allowed is a subset of all gnupg_options
        assert allowed.issubset(gnupg_options)
    except AssertionError:
        raise UsageError("'allowed' isn't a subset of known options, diff: %s"
                         % allowed.difference(gnupg_options))

    ## if we got a list of args, join them
    ##
    ## see TODO file, tag :cleanup:
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
            ## xxx we probably want to use itertools.dropwhile here
            try:
                assert hyphenated in allowed
            except AssertionError as ae:
                dropped = _fix_unsafe(hyphenated)
                log.warn("_is_allowed(): Dropping option '%s'..." % dropped)
                raise ProtectedOption("Option '%s' not supported." % dropped)
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

def _is_string(thing):
    """Python character arrays are a mess.

    If Python2, check if ``thing`` is a ``unicode()`` or ``str()``.
    If Python3, check if ``thing`` is a ``str()``.

    :param thing: The thing to check.
    :returns: ``True`` if ``thing`` is a "string" according to whichever
              version of Python we're running in.
    """
    if _util._py3k: return isinstance(thing, str)
    else: return isinstance(thing, basestring)

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

    If you're asking, "Is this *really* necessary?": No, not really -- we could
    just do a check as described here: https://xkcd.com/1181/

    :param str args: (optional) The boolean arguments which will be passed to
                     the GnuPG process.
    :rtype: str
    :returns: ``sanitised``
    """

    ## see TODO file, tag :cleanup:sanitise:

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
        checked = str()
        none_options        = _get_options_group("none_options")
        hex_options         = _get_options_group("hex_options")
        hex_or_none_options = _get_options_group("hex_or_none_options")

        if not _util._py3k:
            if not isinstance(arg, list) and isinstance(arg, unicode):
                arg = str(arg)

        try:
            flag = _is_allowed(arg)
            assert flag is not None, "_check_option(): got None for flag"
        except (AssertionError, ProtectedOption) as error:
            log.warn("_check_option(): %s" % error.message)
        else:
            checked += (flag + ' ')

            if _is_string(value):
                values = value.split(' ')
                for v in values:
                    ## these can be handled separately, without _fix_unsafe(),
                    ## because they are only allowed if they pass the regex
                    if (flag in none_options) and (v is None):
                        continue

                    if flag in hex_options:
                        if _is_hex(v): checked += (v + " ")
                        else:
                            log.debug("'%s %s' not hex." % (flag, v))
                            if (flag in hex_or_none_options) and (v is None):
                                log.debug("Allowing '%s' for all keys" % flag)
                        continue

                    elif flag in ['--keyserver']:
                        host = _check_keyserver(v)
                        if host:
                            log.debug("Setting keyserver: %s" % host)
                            checked += (v + " ")
                        else: log.debug("Dropping keyserver: %s" % v)
                        continue

                    ## the rest are strings, filenames, etc, and should be
                    ## shell escaped:
                    val = _fix_unsafe(v)
                    try:
                        assert not val is None
                        assert not val.isspace()
                        assert not v is None
                        assert not v.isspace()
                    except:
                        log.debug("Dropping %s %s" % (flag, v))
                        continue

                    if flag in ['--encrypt', '--encrypt-files', '--decrypt',
                                '--decrypt-files', '--import', '--verify']:
                        if _util._is_file(val) or \
                                (flag == '--verify' and val == '-'):
                            checked += (val + " ")
                        else:
                            log.debug("%s not file: %s" % (flag, val))

                    elif flag in ['--cipher-algo', '--personal-cipher-prefs',
                                  '--personal-cipher-preferences']:
                        legit_algos = _check_preferences(val, 'cipher')
                        if legit_algos: checked += (legit_algos + " ")
                        else: log.debug("'%s' is not cipher" % val)

                    elif flag in ['--compress-algo', '--compression-algo',
                                  '--personal-compress-prefs',
                                  '--personal-compress-preferences']:
                        legit_algos = _check_preferences(val, 'compress')
                        if legit_algos: checked += (legit_algos + " ")
                        else: log.debug("'%s' not compress algo" % val)

                    else:
                        checked += (val + " ")
                        log.debug("_check_option(): No checks for %s" % val)

        return checked

    is_flag = lambda x: x.startswith('--')

    def _make_filo(args_string):
        filo = arg.split(' ')
        filo.reverse()
        log.debug("_make_filo(): Converted to reverse list: %s" % filo)
        return filo

    def _make_groups(filo):
        groups = {}
        while len(filo) >= 1:
            last = filo.pop()
            if is_flag(last):
                log.debug("Got arg: %s" % last)
                if last == '--verify':
                    groups[last] = str(filo.pop())
                    ## accept the read-from-stdin arg:
                    if len(filo) >= 1 and filo[len(filo)-1] == '-':
                        groups[last] += str(' - ') ## gross hack
                        filo.pop()
                else:
                    groups[last] = str()
                while len(filo) > 1 and not is_flag(filo[len(filo)-1]):
                    log.debug("Got value: %s" % filo[len(filo)-1])
                    groups[last] += (filo.pop() + " ")
                else:
                    if len(filo) == 1 and not is_flag(filo[0]):
                        log.debug("Got value: %s" % filo[0])
                        groups[last] += filo.pop()
            else:
                log.warn("_make_groups(): Got solitary value: %s" % last)
                groups["xxx"] = last
        return groups

    def _check_groups(groups):
        log.debug("Got groups: %s" % groups)
        checked_groups = []
        for a,v in groups.items():
            v = None if len(v) == 0 else v
            safe = _check_option(a, v)
            if safe is not None and not safe.strip() == "":
                log.debug("Appending option: %s" % safe)
                checked_groups.append(safe)
            else:
                log.warn("Dropped option: '%s %s'" % (a,v))
        return checked_groups

    if args is not None:
        option_groups = {}
        for arg in args:
            ## if we're given a string with a bunch of options in it split
            ## them up and deal with them separately
            if (not _util._py3k and isinstance(arg, basestring)) \
                    or (_util._py3k and isinstance(arg, str)):
                log.debug("Got arg string: %s" % arg)
                if arg.find(' ') > 0:
                    filo = _make_filo(arg)
                    option_groups.update(_make_groups(filo))
                else:
                    option_groups.update({ arg: "" })
            elif isinstance(arg, list):
                log.debug("Got arg list: %s" % arg)
                arg.reverse()
                option_groups.update(_make_groups(arg))
            else:
                log.warn("Got non-str/list arg: '%s', type '%s'"
                         % (arg, type(arg)))
        checked = _check_groups(option_groups)
        sanitised = ' '.join(x for x in checked)
        return sanitised
    else:
        log.debug("Got None for args")

def _sanitise_list(arg_list):
    """A generator for iterating through a list of gpg options and sanitising
    them.

    :param list arg_list: A list of options and flags for GnuPG.
    :rtype: generator
    :returns: A generator whose next() method returns each of the items in
              ``arg_list`` after calling ``_sanitise()`` with that item as a
              parameter.
    """
    if isinstance(arg_list, list):
        for arg in arg_list:
            safe_arg = _sanitise(arg)
            if safe_arg != "":
                yield safe_arg

def _get_options_group(group=None):
    """Get a specific group of options which are allowed."""

    #: These expect a hexidecimal keyid as their argument, and can be parsed
    #: with :func:`_is_hex`.
    hex_options = frozenset(['--check-sigs',
                             '--default-key',
                             '--default-recipient',
                             '--delete-keys',
                             '--delete-secret-keys',
                             '--delete-secret-and-public-keys',
                             '--desig-revoke',
                             '--export',
                             '--export-secret-keys',
                             '--export-secret-subkeys',
                             '--fingerprint',
                             '--gen-revoke',
                             '--list-key',
                             '--list-keys',
                             '--list-public-keys',
                             '--list-secret-keys',
                             '--list-sigs',
                             '--recipient',
                             '--recv-keys',
                             '--send-keys',
                             ])
    #: These options expect value which are left unchecked, though still run
    #: through :func:`_fix_unsafe`.
    unchecked_options = frozenset(['--list-options',
                                   '--passphrase-fd',
                                   '--status-fd',
                                   '--verify-options',
                               ])
    #: These have their own parsers and don't really fit into a group
    other_options = frozenset(['--debug-level',
                               '--keyserver',

                           ])
    #: These should have a directory for an argument
    dir_options = frozenset(['--homedir',
                             ])
    #: These expect a keyring or keyfile as their argument
    keyring_options = frozenset(['--keyring',
                                 '--primary-keyring',
                                 '--secret-keyring',
                                 '--trustdb-name',
                                 ])
    #: These expect a filename (or the contents of a file as a string) or None
    #: (meaning that they read from stdin)
    file_or_none_options = frozenset(['--decrypt',
                                      '--decrypt-files',
                                      '--encrypt',
                                      '--encrypt-files',
                                      '--import',
                                      '--verify',
                                      '--verify-files',
                                      ])
    #: These options expect a string. see :func:`_check_preferences`.
    pref_options = frozenset(['--digest-algo',
                              '--cipher-algo',
                              '--compress-algo',
                              '--compression-algo',
                              '--cert-digest-algo',
                              '--personal-digest-prefs',
                              '--personal-digest-preferences',
                              '--personal-cipher-prefs',
                              '--personal-cipher-preferences',
                              '--personal-compress-prefs',
                              '--personal-compress-preferences',
                              '--print-md',
                              ])
    #: These options expect no arguments
    none_options = frozenset(['--always-trust',
                              '--armor',
                              '--armour',
                              '--batch',
                              '--check-sigs',
                              '--check-trustdb',
                              '--clearsign',
                              '--debug-all',
                              '--default-recipient-self',
                              '--detach-sign',
                              '--export',
                              '--export-ownertrust',
                              '--export-secret-keys',
                              '--export-secret-subkeys',
                              '--fingerprint',
                              '--fixed-list-mode',
                              '--gen-key',
                              '--import-ownertrust',
                              '--list-config',
                              '--list-key',
                              '--list-keys',
                              '--list-packets',
                              '--list-public-keys',
                              '--list-secret-keys',
                              '--list-sigs',
                              '--no-default-keyring',
                              '--no-default-recipient',
                              '--no-emit-version',
                              '--no-options',
                              '--no-tty',
                              '--no-use-agent',
                              '--no-verbose',
                              '--print-mds',
                              '--quiet',
                              '--sign',
                              '--symmetric',
                              '--use-agent',
                              '--verbose',
                              '--version',
                              '--with-colons',
                              '--yes',
                              ])
    #: These options expect either None or a hex string
    hex_or_none_options = hex_options.intersection(none_options)
    allowed = hex_options.union(unchecked_options, other_options, dir_options,
                                keyring_options, file_or_none_options,
                                pref_options, none_options)

    if group and group in locals().keys():
        return locals()[group]

def _get_all_gnupg_options():
    """Get all GnuPG options and flags.

    This is hardcoded within a local scope to reduce the chance of a tampered
    GnuPG binary reporting falsified option sets, i.e. because certain options
    (namedly the '--no-options' option, which prevents the usage of gpg.conf
    files) are necessary and statically specified in
    :meth:`gnupg.GPG._makeargs`, if the inputs into Python are already
    controlled, and we were to summon the GnuPG binary to ask it for its
    options, it would be possible to receive a falsified options set missing
    the '--no-options' option in response. This seems unlikely, and the method
    is stupid and ugly, but at least we'll never have to debug whether or not
    an option *actually* disappeared in a different GnuPG version, or some
    funny business is happening.

    These are the options as of GnuPG 1.4.12; the current stable branch of the
    2.1.x tree contains a few more -- if you need them you'll have to add them
    in here.

    :ivar frozenset gnupg_options: All known GPG options and flags.
    :rtype: frozenset
    :returns: ``gnupg_options``
    """
    three_hundred_eighteen = ("""
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

    # These are extra options which only exist for GnuPG>=2.0.0
    three_hundred_eighteen.append('--export-ownertrust')
    three_hundred_eighteen.append('--import-ownertrust')

    gnupg_options = frozenset(three_hundred_eighteen)
    return gnupg_options

def nodata(status_code):
    """Translate NODATA status codes from GnuPG to messages."""
    lookup = {
        '1': 'No armored data.',
        '2': 'Expected a packet but did not find one.',
        '3': 'Invalid packet found, this may indicate a non OpenPGP message.',
        '4': 'Signature expected but not found.' }
    for key, value in lookup.items():
        if str(status_code) == key:
            return value

def progress(status_code):
    """Translate PROGRESS status codes from GnuPG to messages."""
    lookup = {
        'pk_dsa': 'DSA key generation',
        'pk_elg': 'Elgamal key generation',
        'primegen': 'Prime generation',
        'need_entropy': 'Waiting for new entropy in the RNG',
        'tick': 'Generic tick without any special meaning - still working.',
        'starting_agent': 'A gpg-agent was started.',
        'learncard': 'gpg-agent or gpgsm is learning the smartcard data.',
        'card_busy': 'A smartcard is still working.' }
    for key, value in lookup.items():
        if str(status_code) == key:
            return value


class GenKey(object):
    """Handle status messages for key generation.

    Calling the GenKey.__str__() method of this class will return the
    generated key's fingerprint, or a status string explaining the results.
    """
    def __init__(self, gpg):
        self._gpg = gpg
        ## this should get changed to something more useful, like 'key_type'
        #: 'P':= primary, 'S':= subkey, 'B':= both
        self.type = None
        self.fingerprint = None
        self.status = None
        self.subkey_created = False
        self.primary_created = False
        #: This will store the filename of the key's public keyring if
        #: :meth:`GPG.gen_key_input` was called with ``separate_keyring=True``
        self.keyring = None
        #: This will store the filename of the key's secret keyring if
        #: :meth:`GPG.gen_key_input` was called with ``separate_keyring=True``
        self.secring = None

    def __nonzero__(self):
        if self.fingerprint: return True
        return False
    __bool__ = __nonzero__

    def __str__(self):
        if self.fingerprint:
            return self.fingerprint
        else:
            if self.status is not None:
                return self.status
            else:
                return False

    def _handle_status(self, key, value):
        """Parse a status code from the attached GnuPG process.

        :raises: :exc:`ValueError` if the status message is unknown.
        """
        if key in ("GOOD_PASSPHRASE"):
            pass
        elif key == "KEY_NOT_CREATED":
            self.status = 'key not created'
        elif key == "KEY_CREATED":
            (self.type, self.fingerprint) = value.split()
            self.status = 'key created'
        elif key == "NODATA":
            self.status = nodata(value)
        elif key == "PROGRESS":
            self.status = progress(value.split(' ', 1)[0])
        else:
            raise ValueError("Unknown status message: %r" % key)

        if self.type in ('B', 'P'):
            self.primary_created = True
        if self.type in ('B', 'S'):
            self.subkey_created = True

class DeleteResult(object):
    """Handle status messages for --delete-keys and --delete-secret-keys"""
    def __init__(self, gpg):
        self._gpg = gpg
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
        self._gpg = gpg

    def __nonzero__(self):
        """Override the determination for truthfulness evaluation.

        :rtype: bool
        :returns: True if we have a valid signature, False otherwise.
        """
        return self.fingerprint is not None
    __bool__ = __nonzero__

    def __str__(self):
        return self.data.decode(self._gpg._encoding, self._gpg._decode_errors)

    def _handle_status(self, key, value):
        """Parse a status code from the attached GnuPG process.

        :raises: :exc:`ValueError` if the status message is unknown.
        """
        if key in ("USERID_HINT", "NEED_PASSPHRASE", "BAD_PASSPHRASE",
                   "GOOD_PASSPHRASE", "BEGIN_SIGNING", "CARDCTRL",
                   "INV_SGNR", "SIGEXPIRED"):
            pass
        elif key == "SIG_CREATED":
            (self.sig_type, self.sig_algo, self.sig_hash_algo,
             self.what, self.timestamp, self.fingerprint) = value.split()
        elif key == "KEYEXPIRED":
            self.status = "skipped signing key, key expired"
            if (value is not None) and (len(value) > 0):
                 self.status += " on {}".format(str(value))
        elif key == "KEYREVOKED":
            self.status = "skipped signing key, key revoked"
            if (value is not None) and (len(value) > 0):
                 self.status += " on {}".format(str(value))
        elif key == "NODATA":
            self.status = nodata(value)
        else:
            raise ValueError("Unknown status message: %r" % key)

class ListKeys(list):
    """Handle status messages for --list-keys.

    Handles pub and uid (relating the latter to the former).  Don't care about
    the following attributes/status messages (from doc/DETAILS):

    |  crt = X.509 certificate
    |  crs = X.509 certificate and private key available
    |  ssb = secret subkey (secondary key)
    |  uat = user attribute (same as user id except for field 10).
    |  sig = signature
    |  rev = revocation signature
    |  pkd = public key data (special field format, see below)
    |  grp = reserved for gpgsm
    |  rvk = revocation key
    """

    def __init__(self, gpg):
        super(ListKeys, self).__init__()
        self._gpg = gpg
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
    _ok_reason = {'0': 'Not actually changed',
                  '1': 'Entirely new key',
                  '2': 'New user IDs',
                  '4': 'New signatures',
                  '8': 'New subkeys',
                  '16': 'Contains private key',
                  '17': 'Contains private key',}

    _problem_reason = { '0': 'No specific reason given',
                        '1': 'Invalid Certificate',
                        '2': 'Issuer Certificate missing',
                        '3': 'Certificate Chain too long',
                        '4': 'Error storing certificate', }

    _fields = '''count no_user_id imported imported_rsa unchanged
    n_uids n_subk n_sigs n_revoc sec_read sec_imported sec_dups
    not_imported'''.split()
    _counts = collections.OrderedDict(
        zip(_fields, [int(0) for x in range(len(_fields))]) )

    #: A list of strings containing the fingerprints of the GnuPG keyIDs
    #: imported.
    fingerprints = list()

    #: A list containing dictionaries with information gathered on keys
    #: imported.
    results = list()

    def __init__(self, gpg):
        self._gpg = gpg
        self.counts = self._counts

    def __nonzero__(self):
        """Override the determination for truthfulness evaluation.

        :rtype: bool
        :returns: True if we have immport some keys, False otherwise.
        """
        if self.counts.not_imported > 0: return False
        if len(self.fingerprints) == 0: return False
        return True
    __bool__ = __nonzero__

    def _handle_status(self, key, value):
        """Parse a status code from the attached GnuPG process.

        :raises: :exc:`ValueError` if the status message is unknown.
        """
        if key == "IMPORTED":
            # this duplicates info we already see in import_ok & import_problem
            pass
        elif key == "NODATA":
            self.results.append({'fingerprint': None,
                                 'status': 'No valid data found'})
        elif key == "IMPORT_OK":
            reason, fingerprint = value.split()
            reasons = []
            for code, text in self._ok_reason.items():
                if int(reason) == int(code):
                    reasons.append(text)
            reasontext = '\n'.join(reasons) + "\n"
            self.results.append({'fingerprint': fingerprint,
                                 'status': reasontext})
            self.fingerprints.append(fingerprint)
        elif key == "IMPORT_PROBLEM":
            try:
                reason, fingerprint = value.split()
            except:
                reason = value
                fingerprint = '<unknown>'
            self.results.append({'fingerprint': fingerprint,
                                 'status': self._problem_reason[reason]})
        elif key == "IMPORT_RES":
            import_res = value.split()
            for x in self.counts.keys():
                self.counts[x] = int(import_res.pop(0))
        elif key == "KEYEXPIRED":
            res = {'fingerprint': None,
                   'status': 'Key expired'}
            self.results.append(res)
        ## Accoring to docs/DETAILS L859, SIGEXPIRED is obsolete:
        ## "Removed on 2011-02-04. This is deprecated in favor of KEYEXPIRED."
        elif key == "SIGEXPIRED":
            res = {'fingerprint': None,
                   'status': 'Signature expired'}
            self.results.append(res)
        else:
            raise ValueError("Unknown status message: %r" % key)

    def summary(self):
        l = []
        l.append('%d imported' % self.counts['imported'])
        if self.counts['not_imported']:
            l.append('%d not imported' % self.counts['not_imported'])
        return ', '.join(l)


class Verify(object):
    """Parser for status messages from GnuPG for certifications and signature
    verifications.

    People often mix these up, or think that they are the same thing. While it
    is true that certifications and signatures *are* the same cryptographic
    operation -- and also true that both are the same as the decryption
    operation -- a distinction is made for important reasons.

    A certification:
        * is made on a key,
        * can help to validate or invalidate the key owner's identity,
        * can assign trust levels to the key (or to uids and/or subkeys that
          the key contains),
        * and can be used in absense of in-person fingerprint checking to try
          to build a path (through keys whose fingerprints have been checked)
          to the key, so that the identity of the key's owner can be more
          reliable without having to actually physically meet in person.

    A signature:
        * is created for a file or other piece of data,
        * can help to prove that the data hasn't been altered,
        * and can help to prove that the data was sent by the person(s) in
          possession of the private key that created the signature, and for
          parsing portions of status messages from decryption operations.

    There are probably other things unique to each that have been
    scatterbrainedly omitted due to the programmer sitting still and staring
    at GnuPG debugging logs for too long without snacks, but that is the gist
    of it.
    """

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
        """Create a parser for verification and certification commands.

        :param gpg: An instance of :class:`gnupg.GPG`.
        """
        self._gpg = gpg
        #: True if the signature is valid, False otherwise.
        self.valid = False
        #: A string describing the status of the signature verification.
        #: Can be one of ``signature bad``, ``signature good``,
        #: ``signature valid``, ``signature error``, ``decryption failed``,
        #: ``no public key``, ``key exp``, or ``key rev``.
        self.status = None
        #: The fingerprint of the signing keyid.
        self.fingerprint = None
        #: The fingerprint of the corresponding public key, which may be
        #: different if the signature was created with a subkey.
        self.pubkey_fingerprint = None
        #: The keyid of the signing key.
        self.key_id = None
        #: The id of the signature itself.
        self.signature_id = None
        #: The creation date of the signing key.
        self.creation_date = None
        #: The timestamp of the purported signature, if we are unable to parse
        #: and/or validate it.
        self.timestamp = None
        #: The timestamp for when the valid signature was created.
        self.sig_timestamp = None
        #: The userid of the signing key which was used to create the
        #: signature.
        self.username = None
        #: When the signing key is due to expire.
        self.expire_timestamp = None
        #: An integer 0-4 describing the trust level of the signature.
        self.trust_level = None
        #: The string corresponding to the ``trust_level`` number.
        self.trust_text = None

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


class Crypt(Verify):
    """Parser for internal status messages from GnuPG for ``--encrypt``,
    ``--decrypt``, and ``--decrypt-files``.
    """
    def __init__(self, gpg):
        Verify.__init__(self, gpg)
        self._gpg = gpg
        #: A string containing the encrypted or decrypted data.
        self.data = ''
        #: True if the decryption/encryption process turned out okay.
        self.ok = False
        #: A string describing the current processing status, or error, if one
        #: has occurred.
        self.status = None
        self.data_format = None
        self.data_timestamp = None
        self.data_filename = None

    def __nonzero__(self):
        if self.ok: return True
        return False
    __bool__ = __nonzero__

    def __str__(self):
        """The str() method for a :class:`Crypt` object will automatically return the
        decoded data string, which stores the encryped or decrypted data.

        In other words, these two statements are equivalent:

        >>> assert decrypted.data == str(decrypted)

        """
        return self.data.decode(self._gpg._encoding, self._gpg._decode_errors)

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
        elif key == "NEED_TRUSTDB":
            self._gpg._create_trustdb()
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
        elif key == "KEYREVOKED":
            self.status = 'key revoked'
        elif key == "SIG_CREATED":
            self.status = 'sig created'
        elif key == "SIGEXPIRED":
            self.status = 'sig expired'
        elif key == "PLAINTEXT":
            fmt, dts = value.split(' ', 1)
            if dts.find(' ') > 0:
                self.data_timestamp, self.data_filename = dts.split(' ', 1)
            else:
                self.data_timestamp = dts
            ## GnuPG gives us a hex byte for an ascii char corresponding to
            ## the data format of the resulting plaintext,
            ## i.e. '62'→'b':= binary data
            self.data_format = chr(int(str(fmt), 16))
        else:
            super(Crypt, self)._handle_status(key, value)

class ListPackets(object):
    """Handle status messages for --list-packets."""

    def __init__(self, gpg):
        self._gpg = gpg
        #: A string describing the current processing status, or error, if one
        #: has occurred.
        self.status = None
        #: True if the passphrase to a public/private keypair is required.
        self.need_passphrase = None
        #: True if a passphrase for a symmetric key is required.
        self.need_passphrase_sym = None
        #: The keyid and uid which this data is encrypted to.
        self.userid_hint = None

    def _handle_status(self, key, value):
        """Parse a status code from the attached GnuPG process.

        :raises: :exc:`ValueError` if the status message is unknown.
        """
        if key == 'NODATA':
            self.status = nodata(value)
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
        elif key in ('NO_SECKEY', 'BEGIN_DECRYPTION', 'DECRYPTION_FAILED',
                     'END_DECRYPTION'):
            pass
        else:
            raise ValueError("Unknown status message: %r" % key)
