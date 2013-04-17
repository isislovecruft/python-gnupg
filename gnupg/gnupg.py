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
"""
gnupg.py
========
A Python interface to GnuPG.

This is a modified version of python-gnupg-0.3.0, which was created by Vinay
Sajip, which itself is a modification of GPG.py written by Steve Traugott,
which in turn is a modification of the pycrypto GnuPG interface written by
A.M. Kuchling.

This version is patched to exclude calls to :class:`subprocess.Popen([...],
shell=True)`, and it also attempts to provide sanitization of arguments
presented to gnupg, in order to avoid potential vulnerabilities.

:Info: see <https://www.github.com/isislovecruft/python-gnupg>
:Authors: A.M. Kuchling, Steve Traugott, Vinay Sajip, Isis Lovecruft
:Date: $Date: 2013-04-04 01:11:01 +0000 (Thursday, April 4, 2013) $
:Description: Documentation of python-gnupg, a Python module for GnuPG.


Previous Authors' Documentation
-------------------------------

Steve Traugott's documentation:

    Portions of this module are derived from A.M. Kuchling's well-designed
    GPG.py, using Richard Jones' updated version 1.3, which can be found in
    the pycrypto CVS repository on Sourceforge:

    http://pycrypto.cvs.sourceforge.net/viewvc/pycrypto/gpg/GPG.py

    This module is *not* forward-compatible with amk's; some of the old
    interface has changed.  For instance, since I've added decrypt
    functionality, I elected to initialize with a 'gpghome' argument instead
    of 'keyring', so that gpg can find both the public and secret keyrings.
    I've also altered some of the returned objects in order for the caller to
    not have to know as much about the internals of the result classes.

    While the rest of ISconf is released under the GPL, I am releasing this
    single file under the same terms that A.M. Kuchling used for pycrypto.

    Steve Traugott, stevegt@terraluna.org
    Thu Jun 23 21:27:20 PDT 2005


Vinay Sajip's documentation:

    This version of the module has been modified from Steve Traugott's version
    (see http://trac.t7a.org/isconf/browser/trunk/lib/python/isconf/GPG.py) by
    Vinay Sajip to make use of the subprocess module (Steve's version uses
    os.fork() and so does not work on Windows). Renamed to gnupg.py to avoid
    confusion with the previous versions.

    A unittest harness (test_gnupg.py) has also been added.

    Modifications Copyright (C) 2008-2012 Vinay Sajip. All rights reserved.

"""

__author__ = "Isis Agora Lovecruft"
__module__ = 'gnupg'
__version__ = "0.4.0"


try:
    from io import StringIO
    from io import BytesIO
except ImportError:
    from cStringIO import StringIO

from subprocess import Popen
from subprocess import PIPE

import codecs
## For AOS, the locale module will need to point to a wrapper around the
## java.util.Locale class.
## See https://github.com/isislovecruft/android-locale-hack
import locale
import logging
import os
import re
import socket
import sys
import tempfile
import threading

from parsers import Verify, Crypt, DeleteResult, ImportResult
from parsers import GenKey, Sign, ListKeys, ListPackets
from parsers import _fix_unsafe, _sanitise, _is_allowed, _sanitise_list
from util    import logger, _conf

import util


def _copy_data(instream, outstream):
    """Copy data from one stream to another.

    :type instream: :class:`io.BytesIO` or :class:`io.StringIO` or file
    :param instream: A byte stream or open file to read from.
    :param file outstream: The file descriptor of a tmpfile to write to.
    """
    sent = 0

    try:
        #assert (util._is_stream(instream)
        #        or isinstance(instream, file)), "instream not stream or file"
        assert isinstance(outstream, file), "outstream is not a file"
    except AssertionError as ae:
        logger.exception(ae)
        return

    if hasattr(sys.stdin, 'encoding'):
        enc = sys.stdin.encoding
    else:
        enc = 'ascii'

    while True:
        data = instream.read(1024)
        if len(data) == 0:
            break
        sent += len(data)
        logger.debug("_copy_data(): sending chunk (%d):\n%s" % (sent, data[:256]))
        try:
            outstream.write(data)
        except UnicodeError:
            try:
                outstream.write(data.encode(enc))
            except IOError:
                logger.exception('_copy_data(): Error sending data: Broken pipe')
                break
        except IOError:
            # Can get 'broken pipe' errors even when all data was sent
            logger.exception('_copy_data(): Error sending data: Broken pipe')
            break
    try:
        outstream.close()
    except IOError:
        logger.exception('_copy_data(): Got IOError while closing %s' % outstream)
    else:
        logger.debug("_copy_data(): Closed output, %d bytes sent." % sent)

def _threaded_copy_data(instream, outstream):
    """Copy data from one stream to another in a separate thread.

    Wraps ``_copy_data()`` in a :class:`threading.Thread`.

    :type instream: :class:`io.BytesIO` or :class:`io.StringIO`
    :param instream: A byte stream to read from.
    :param file outstream: The file descriptor of a tmpfile to write to.
    """
    copy_thread = threading.Thread(target=_copy_data,
                                   args=(instream, outstream))
    copy_thread.setDaemon(True)
    logger.debug('_threaded_copy_data(): %r, %r, %r', copy_thread,
                 instream, outstream)
    copy_thread.start()
    return copy_thread

def _write_passphrase(stream, passphrase, encoding):
    passphrase = '%s\n' % passphrase
    passphrase = passphrase.encode(encoding)
    stream.write(passphrase)
    logger.debug("_write_passphrase(): Wrote passphrase.")


class GPG(object):
    """Encapsulate access to the gpg executable"""
    _decode_errors = 'strict'

    _result_map = {'crypt': Crypt,
                   'delete': DeleteResult,
                   'generate': GenKey,
                   'import': ImportResult,
                   'list': ListKeys,
                   'sign': Sign,
                   'verify': Verify,}

    def __init__(self, gpgbinary=None, gpghome=None, verbose=False,
                 use_agent=False, keyring=None, secring=None, pubring=None,
                 options=None):
        """Initialize a GnuPG process wrapper.

        :param str gpgbinary: Name for GnuPG binary executable. If the absolute
                              path is not given, the evironment variable $PATH
                              is searched for the executable and checked that
                              the real uid/gid of the user has sufficient
                              permissions.
        :param str gpghome: Full pathname to directory containing the public
                            and private keyrings. Default is whatever GnuPG
                            defaults to.
        :param str keyring: raises :exc:DeprecationWarning. Use :param:pubring.
        :param str secring: Name of alternative secret keyring file to use. If
                            left unspecified, this will default to using
                            'secring.gpg' in the :param:gpghome directory, and
                            create that file if it does not exist.
        :param str pubring: Name of alternative public keyring file to use. If
                            left unspecified, this will default to using
                            'pubring.gpg' in the :param:gpghome directory, and
                            create that file if it does not exist.
        :param list options: A list of additional options to pass to the GPG
                             binary.
        :raises: :exc:`RuntimeError` with explanation message if there is a
                 problem invoking gpg.
        """

        logger.warn("")

        if not gpghome:
            gpghome = _conf
        self.gpghome = _fix_unsafe(gpghome)
        if self.gpghome:
            util._create_gpghome(self.gpghome)
        else:
            message = ("Unsuitable gpg home dir: %s" % gpghome)
            logger.debug("GPG.__init__(): %s" % message)

        self.gpgbinary = util._find_gpgbinary(gpgbinary)

        if keyring is not None:
            raise DeprecationWarning("Option 'keyring' changing to 'secring'")

        secring = 'secring.gpg' if secring is None else _fix_unsafe(secring)
        pubring = 'pubring.gpg' if pubring is None else _fix_unsafe(pubring)
        self.secring = os.path.join(self.gpghome, secring)
        self.pubring = os.path.join(self.gpghome, pubring)

        self.options = _sanitise(options) if options else None

        self.encoding = locale.getpreferredencoding()
        if self.encoding is None: # This happens on Jython!
            self.encoding = sys.stdin.encoding

        try:
            assert self.gpghome is not None, "Got None for self.gpghome"
            assert util._has_readwrite(self.gpghome), ("Home dir %s needs r+w"
                                                       % self.gpghome)
            assert self.gpgbinary, "Could not find gpgbinary %s" % full
            assert isinstance(verbose, bool), "'verbose' must be boolean"
            assert isinstance(use_agent, bool), "'use_agent' must be boolean"
            if self.options:
                assert isinstance(options, str), ("options not formatted: %s"
                                                  % options)
        except (AssertionError, AttributeError) as ae:
            logger.debug("GPG.__init__(): %s" % ae.message)
            raise RuntimeError(ae.message)
        else:
            self.verbose = verbose
            self.use_agent = use_agent

            proc = self._open_subprocess(["--version"])
            result = self._result_map['list'](self)
            self._collect_output(proc, result, stdin=proc.stdin)
            if proc.returncode != 0:
                raise RuntimeError("Error invoking gpg: %s: %s"
                                   % (proc.returncode, result.stderr))

    def _make_args(self, args, passphrase=False):
        """Make a list of command line elements for GPG. The value of ``args``
        will be appended only if it passes the checks in
        :func:parsers._sanitise. The ``passphrase`` argument needs to be True
        if a passphrase will be sent to GPG, else False.
        """
        cmd = [self.gpgbinary, '--status-fd 2 --no-tty']
        if self.gpghome:
            cmd.append('--homedir "%s"' % self.gpghome)
        if self.pubring:
            cmd.append('--no-default-keyring --keyring %s' % self.pubring)
            if self.secring:
                cmd.append('--secret-keyring %s' % self.secring)
        if passphrase:
            cmd.append('--batch --passphrase-fd 0')
        if self.use_agent:
            cmd.append('--use-agent')
        if self.options:
            [cmd.append(opt) for opt in iter(_sanitise_list(self.options))]
        if args:
            [cmd.append(arg) for arg in iter(_sanitise_list(args))]
        return cmd

    def _open_subprocess(self, args=None, passphrase=False):
        """Open a pipe to a GPG subprocess and return the file objects for
        communicating with it.
        """
        cmd = ' '.join(self._make_args(args, passphrase))
        if self.verbose:
            print(cmd)
        logger.debug("_open_subprocess(): %s", cmd)
        return Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)

    def _read_response(self, stream, result):
        """Reads all the stderr output from GPG, taking notice only of lines
        that begin with the magic [GNUPG:] prefix.

        Calls methods on the response object for each valid token found, with
        the arg being the remainder of the status line.
        """
        lines = []
        while True:
            line = stream.readline()
            if len(line) == 0:
                break
            lines.append(line)
            line = line.rstrip()
            if self.verbose:
                print(line)
            logger.debug("%s", line)
            if line[0:9] == '[GNUPG:] ':
                # Chop off the prefix
                line = line[9:]
                L = line.split(None, 1)
                keyword = L[0]
                if len(L) > 1:
                    value = L[1]
                else:
                    value = ""
                result.handle_status(keyword, value)
        result.stderr = ''.join(lines)

    def _read_data(self, stream, result):
        """Read the contents of the file from GPG's stdout."""
        chunks = []
        while True:
            data = stream.read(1024)
            if len(data) == 0:
                break
            logger.debug("chunk: %r" % data[:256])
            chunks.append(data)
        if util._py3k:
            # Join using b'' or '', as appropriate
            result.data = type(data)().join(chunks)
        else:
            result.data = ''.join(chunks)

    def _collect_output(self, process, result, writer=None, stdin=None):
        """Drain the subprocesses output streams, writing the collected output
        to the result. If a writer thread (writing to the subprocess) is given,
        make sure it's joined before returning. If a stdin stream is given,
        close it before returning.
        """
        stderr = codecs.getreader(self.encoding)(process.stderr)
        rr = threading.Thread(target=self._read_response, args=(stderr, result))
        rr.setDaemon(True)
        logger.debug('stderr reader: %r', rr)
        rr.start()

        stdout = process.stdout
        dr = threading.Thread(target=self._read_data, args=(stdout, result))
        dr.setDaemon(True)
        logger.debug('stdout reader: %r', dr)
        dr.start()

        dr.join()
        rr.join()
        if writer is not None:
            writer.join()
        process.wait()
        if stdin is not None:
            try:
                stdin.close()
            except IOError:
                pass
        stderr.close()
        stdout.close()

    def _handle_io(self, args, file, result, passphrase=False, binary=False):
        """Handle a call to GPG - pass input data, collect output data."""
        p = self._open_subprocess(args, passphrase)
        if not binary:
            stdin = codecs.getwriter(self.encoding)(p.stdin)
        else:
            stdin = p.stdin
        if passphrase:
            _write_passphrase(stdin, passphrase, self.encoding)
        writer = _threaded_copy_data(file, stdin)
        self._collect_output(p, result, writer, stdin)
        return result

    #
    # SIGNATURE METHODS
    #
    def sign(self, message, **kwargs):
        """Create a signature for a message or file."""
        if isinstance(message, file):
            result = self._sign_file(message, **kwargs)
        elif not util._is_stream(message):
            f = util._make_binary_stream(message, self.encoding)
            result = self._sign_file(f, **kwargs)
            f.close()
        else:
            logger.error("Unable to sign message '%s' with type %s"
                         % (message, type(message)))
            result = None
        return result

    def _sign_file(self, file, keyid=None, passphrase=None, clearsign=True,
                   detach=False, binary=False):
        """Create a signature for a  file."""
        logger.debug("_sign_file(): %s", file)
        if binary:
            args = ['--sign']
        else:
            args = ['--sign --armor']

        if clearsign:
            args.append("--clearsign")
            if detach:
                logger.warn("Cannot use both --clearsign and --detach-sign.")
                logger.warn("Using default GPG behaviour: --clearsign only.")
        elif detach and not clearsign:
            args.append("--detach-sign")

        if keyid:
            args.append(str("--default-key %s" % keyid))

        result = self._result_map['sign'](self)
        ## We could use _handle_io here except for the fact that if the
        ## passphrase is bad, gpg bails and you can't write the message.
        p = self._open_subprocess(args, passphrase is not None)
        try:
            stdin = p.stdin
            if passphrase:
                _write_passphrase(stdin, passphrase, self.encoding)
            writer = _threaded_copy_data(file, stdin)
        except IOError:
            logger.exception("_sign_file(): Error writing message")
            writer = None
        self._collect_output(p, result, writer, stdin)
        return result

    def verify(self, data):
        """Verify the signature on the contents of the string ``data``.

        >>> gpg = GPG(gpghome="keys")
        >>> input = gpg.gen_key_input(Passphrase='foo')
        >>> key = gpg.gen_key(input)
        >>> assert key
        >>> sig = gpg.sign('hello',keyid=key.fingerprint,passphrase='bar')
        >>> assert not sig
        >>> sig = gpg.sign('hello',keyid=key.fingerprint,passphrase='foo')
        >>> assert sig
        >>> verify = gpg.verify(sig.data)
        >>> assert verify

        """
        f = util._make_binary_stream(data, self.encoding)
        result = self.verify_file(f)
        f.close()
        return result

    def verify_file(self, file, sig_file=None):
        """Verify the signature on the contents of a file or file-like
        object. Can handle embedded signatures as well as detached
        signatures. If using detached signatures, the file containing the
        detached signature should be specified as the ``sig_file``.

        :param file file: A file descriptor object. Its type will be checked
                          with :func:`util._is_file`.
        :param str sig_file: A file containing the GPG signature data for
                             ``file``. If given, ``file`` is verified via this
                             detached signature.
        """

        fn = None
        result = self._result_map['verify'](self)

        if sig_file is None:
            logger.debug("verify_file(): Handling embedded signature")
            args = ["--verify"]
            proc = self._open_subprocess(args)
            writer = _threaded_copy_data(file, proc.stdin)
            self._collect_output(proc, result, writer, stdin=proc.stdin)
        else:
            if not util._is_file(sig_file):
                logger.debug("verify_file(): '%r' is not a file" % sig_file)
                return result
            logger.debug('verify_file(): Handling detached verification')
            sig_fh = None
            try:
                sig_fh = open(sig_file)
                args = ["--verify %s - " % sig_fh.name]
                proc = self._open_subprocess(args)
                writer = _threaded_copy_data(file, proc.stdin)
                self._collect_output(proc, result, stdin=proc.stdin)
            finally:
                if sig_fh and not sig_fh.closed:
                    sig_fh.close()
        return result

    #
    # KEY MANAGEMENT
    #
    def import_keys(self, key_data):
        """
        Import the key_data into our keyring.

        >>> import shutil
        >>> shutil.rmtree("keys")
        >>> gpg = GPG(gpghome="keys")
        >>> input = gpg.gen_key_input()
        >>> result = gpg.gen_key(input)
        >>> print1 = result.fingerprint
        >>> result = gpg.gen_key(input)
        >>> print2 = result.fingerprint
        >>> pubkey1 = gpg.export_keys(print1)
        >>> seckey1 = gpg.export_keys(print1,secret=True)
        >>> seckeys = gpg.list_keys(secret=True)
        >>> pubkeys = gpg.list_keys()
        >>> assert print1 in seckeys.fingerprints
        >>> assert print1 in pubkeys.fingerprints
        >>> str(gpg.delete_keys(print1))
        'Must delete secret key first'
        >>> str(gpg.delete_keys(print1,secret=True))
        'ok'
        >>> str(gpg.delete_keys(print1))
        'ok'
        >>> str(gpg.delete_keys("nosuchkey"))
        'No such key'
        >>> seckeys = gpg.list_keys(secret=True)
        >>> pubkeys = gpg.list_keys()
        >>> assert not print1 in seckeys.fingerprints
        >>> assert not print1 in pubkeys.fingerprints
        >>> result = gpg.import_keys('foo')
        >>> assert not result
        >>> result = gpg.import_keys(pubkey1)
        >>> pubkeys = gpg.list_keys()
        >>> seckeys = gpg.list_keys(secret=True)
        >>> assert not print1 in seckeys.fingerprints
        >>> assert print1 in pubkeys.fingerprints
        >>> result = gpg.import_keys(seckey1)
        >>> assert result
        >>> seckeys = gpg.list_keys(secret=True)
        >>> pubkeys = gpg.list_keys()
        >>> assert print1 in seckeys.fingerprints
        >>> assert print1 in pubkeys.fingerprints
        >>> assert print2 in pubkeys.fingerprints
        """
        ## xxx need way to validate that key_data is actually a valid GPG key
        ##     it might be possible to use --list-packets and parse the output

        result = self._result_map['import'](self)
        logger.debug('import_keys: %r', key_data[:256])
        data = util._make_binary_stream(key_data, self.encoding)
        self._handle_io(['--import'], data, result, binary=True)
        logger.debug('import_keys result: %r', result.__dict__)
        data.close()
        return result

    def recv_keys(self, keyserver, *keyids):
        """Import a key from a keyserver

        >>> import shutil
        >>> shutil.rmtree("keys")
        >>> gpg = GPG(gpghome="keys")
        >>> result = gpg.recv_keys('pgp.mit.edu', '3FF0DB166A7476EA')
        >>> assert result

        """
        safe_keyserver = _fix_unsafe(keyserver)

        result = self._result_map['import'](self)
        data = util._make_binary_stream("", self.encoding)
        args = ['--keyserver', keyserver, '--recv-keys']

        if keyids:
            if keyids is not None:
                safe_keyids = ' '.join(
                    [(lambda: _fix_unsafe(k))() for k in keyids])
                logger.debug('recv_keys: %r', safe_keyids)
                args.extend(safe_keyids)

        self._handle_io(args, data, result, binary=True)
        data.close()
        logger.debug('recv_keys result: %r', result.__dict__)
        return result

    def delete_keys(self, fingerprints, secret=False):
        which='key'
        if secret:
            which='secret-key'
        if util._is_list_or_tuple(fingerprints):
            fingerprints = ' '.join(fingerprints)
        args = ['--batch --delete-%s "%s"' % (which, fingerprints)]
        result = self._result_map['delete'](self)
        p = self._open_subprocess(args)
        self._collect_output(p, result, stdin=p.stdin)
        return result

    def export_keys(self, keyids, secret=False):
        """export the indicated keys. 'keyid' is anything gpg accepts"""
        which=''
        if secret:
            which='-secret-key'
        if util._is_list_or_tuple(keyids):
            keyids = ' '.join(['"%s"' % k for k in keyids])
        args = ["--armor --export%s %s" % (which, keyids)]
        p = self._open_subprocess(args)
        # gpg --export produces no status-fd output; stdout will be
        # empty in case of failure
        #stdout, stderr = p.communicate()
        result = self._result_map['delete'](self) # any result will do
        self._collect_output(p, result, stdin=p.stdin)
        logger.debug('export_keys result: %r', result.data)
        return result.data.decode(self.encoding, self._decode_errors)

    def list_keys(self, secret=False):
        """List the keys currently in the keyring.

        >>> import shutil
        >>> shutil.rmtree("keys")
        >>> gpg = GPG(gpghome="keys")
        >>> input = gpg.gen_key_input()
        >>> result = gpg.gen_key(input)
        >>> print1 = result.fingerprint
        >>> result = gpg.gen_key(input)
        >>> print2 = result.fingerprint
        >>> pubkeys = gpg.list_keys()
        >>> assert print1 in pubkeys.fingerprints
        >>> assert print2 in pubkeys.fingerprints
        """

        which='public-keys'
        if secret:
            which='secret-keys'
        args = "--list-%s --fixed-list-mode --fingerprint --with-colons --no-show-photos" % (which,)
        args = [args]
        p = self._open_subprocess(args)

        # there might be some status thingumy here I should handle... (amk)
        # ...nope, unless you care about expired sigs or keys (stevegt)

        # Get the response information
        result = self._result_map['list'](self)
        self._collect_output(p, result, stdin=p.stdin)
        lines = result.data.decode(self.encoding,
                                   self._decode_errors).splitlines()
        valid_keywords = 'pub uid sec fpr sub'.split()
        for line in lines:
            if self.verbose:
                print(line)
            logger.debug("line: %r", line.rstrip())
            if not line:
                break
            L = line.strip().split(':')
            if not L:
                continue
            keyword = L[0]
            if keyword in valid_keywords:
                getattr(result, keyword)(L)
        return result

    def list_sigs(self, *keyids):
        """xxx implement me

        The GnuPG option '--show-photos', according to the GnuPG manual, "does
        not work with --with-colons", but since we can't rely on all versions
        of GnuPG to explicitly handle this correctly, we should probably
        include it in the args.
        """
        ## we will want to include "--no-show-photos" in the args
        raise NotImplemented("Functionality for '--list-sigs' not implemented.")

    def gen_key(self, input):
        """Generate a GnuPG key through batch file key generation. See
        :meth:`GPG.gen_key_input()` for creating the control input.

        >>> gpg = GPG(gpghome="keys")
        >>> input = gpg.gen_key_input()
        >>> result = gpg.gen_key(input)
        >>> assert result
        >>> result = gpg.gen_key('foo')
        >>> assert not result

        :param dict input: A dictionary of parameters and values for the new
                           key.
        :returns: The result mapping with details of the new key, which is a
                  :class:`parsers.GenKey <GenKey>` object.
        """
        args = ["--gen-key --batch"]
        key = self._result_map['generate'](self)
        f = util._make_binary_stream(input, self.encoding)
        self._handle_io(args, f, key, binary=True)
        f.close()
        return key

    def gen_key_input(self, **kwargs):
        """Generate a batch file for input to :meth:`GPG.gen_key()`.

        The GnuPG batch file key generation feature allows unattended key
        generation by creating a file with special syntax and then providing it
        to: ``gpg --gen-key --batch``:

            Key-Type: RSA
            Key-Length: 4096
            Name-Real: Autogenerated Key
            Name-Email: %s@%s
            Expire-Date: 2014-04-01
            %pubring foo.gpg
            %secring sec.gpg
            %commit

            Key-Type: DSA
            Key-Length: 1024
            Subkey-Type: ELG-E
            Subkey-Length: 1024
            Name-Real: Joe Tester
            Name-Comment: with stupid passphrase
            Name-Email: joe@foo.bar
            Expire-Date: 0
            Passphrase: abc
            %pubring foo.pub
            %secring foo.sec
            %commit

        see http://www.gnupg.org/documentation/manuals/gnupg-devel/Unattended-GPG-key-generation.html#Unattended-GPG-key-generation
        for more details.

        >>> gpg = GPG(gpghome="keys")
        >>> params = {'name_real':'python-gnupg tester', 'name_email':'test@ing'}
        >>> key_input = gpg.gen_key_input(**params)
        >>> result = gpg.gen_key(input)
        >>> assert result

        :param str name_real: The uid name for the generated key.
        :param str name_email: The uid email for the generated key. (default:
            $USERNAME@$HOSTNAME)
        :param str name_comment: The comment in the uid of the generated key.
        :param str key_type: One of 'RSA', 'DSA', or 'ELG-E'. (default: 'RSA')
        :param int key_length: The length in bytes of the new key.
            (default: 4096)
        :param str subkey_type: If ``key_type`` is 'RSA', an additional subkey
            can be generated, and it's type must also be 'RSA'. If ``key_type``
            is 'DSA', then the only subkey type which can be generated is
            'ELG-E'.
        :param int subkey_length: The length in bytes of the new subkey.
        :type expire: int or str
        :param expire: If an integer, the number of days before the key will
            expire; if 0, the key will not expire. Otherwise, this can be given
            as a string in the form <n>w or <n>m or <n>y, i.e. "5m" would mean
            that the key will expire in five months, "1w" would expire in one
            week, and "3y" would expire in three years. (default: "1y")
        :param str passphrase: The passphrase for the new key.
        """

        parms = {}
        for key, val in list(kwargs.items()):
            key = key.replace('_','-').title()
            if str(val).strip():    # skip empty strings
                parms[key] = val
        parms.setdefault('Key-Type', 'RSA')
        parms.setdefault('Key-Length', 4096)
        parms.setdefault('Name-Real', "Autogenerated Key")
        parms.setdefault('Name-Comment', "Generated by python-gnupg")
        try:
            logname = os.environ['LOGNAME']
        except KeyError:
            logname = os.environ['USERNAME']
        hostname = socket.gethostname()
        parms.setdefault('Name-Email', "%s@%s"
                         % (logname.replace(' ', '_'), hostname))
        out = "Key-Type: %s\n" % parms.pop('Key-Type')
        for key, val in list(parms.items()):
            out += "%s: %s\n" % (key, val)
        out += "%%pubring %s\n" % self.pubring
        out += "%%secring %s\n" % self.secring
        out += "%commit\n"
        return out

    #
    # ENCRYPTION
    #
    def encrypt_file(self, file, recipients, sign=None,
                     always_trust=False, passphrase=None,
                     armor=True, output=None, symmetric=False):
        """Encrypt the message read from ``file``.

        :type file: file or :class:BytesIO
        :param file: The file or bytestream to encrypt.
        :type recipients: str or list or tuple
        :param recipients: The recipients to encrypt to. Recipients may be
                           specified by UID or keyID/fingerprint.
        :param str sign: The keyID to use for signing, i.e.
                         "gpg --sign --default-key A3ADB67A2CDB8B35 ..."
        :param bool always_trust: If True, ignore trust warnings on recipient
                                  keys. If False, display trust warnings.
                                  (default: False)
        :param bool passphrase: If True, use the stored passphrase for our
                                secret key.

        :param bool armor: If True, ascii armor the encrypted output; if False,
                           the encrypted output will be in binary
                           format. (default: True)

        :param str output: The output file to write to. If not specified, the
                           encrypted output is returned, and thus should be
                           stored as an object in Python. For example:

        >>> gpg = gnupg.GPG(gpghome='./tmp_test')

        """
        if output:  # write the output to a file with the specified name
            if os.path.exists(output):
                os.remove(output) # to avoid overwrite confirmation message
            args.append('--output "%s"' % output)
        args = ['--encrypt']
        if symmetric:
            args = ['--symmetric']
        else:
            args = ['--encrypt']
            if not util._is_list_or_tuple(recipients):
                recipients = (recipients,)
            for recipient in recipients:
                args.append('--recipient "%s"' % recipient)
        if armor:
            args.append('--armor')
        if sign:
            args.append('--sign --default-key "%s"' % sign)
        if always_trust:
            args.append("--always-trust")
        result = self._result_map['crypt'](self)
        self._handle_io(args, file, result, passphrase=passphrase, binary=True)
        logger.debug('encrypt result: %r', result.data)
        return result

    def encrypt(self, data, recipients, **kwargs):
        """Encrypt the message contained in ``data`` to ``recipients``.

        >>> import shutil
        >>> if os.path.exists("keys"):
        ...     shutil.rmtree("keys")
        >>> gpg = GPG(gpghome="keys")
        >>> input = gpg.gen_key_input(passphrase='foo')
        >>> result = gpg.gen_key(input)
        >>> print1 = result.fingerprint
        >>> input = gpg.gen_key_input()
        >>> result = gpg.gen_key(input)
        >>> print2 = result.fingerprint
        >>> result = gpg.encrypt("hello",print2)
        >>> message = str(result)
        >>> assert message != 'hello'
        >>> result = gpg.decrypt(message)
        >>> assert result
        >>> str(result)
        'hello'
        >>> result = gpg.encrypt("hello again",print1)
        >>> message = str(result)
        >>> result = gpg.decrypt(message,passphrase='bar')
        >>> result.status in ('decryption failed', 'bad passphrase')
        True
        >>> assert not result
        >>> result = gpg.decrypt(message,passphrase='foo')
        >>> result.status == 'decryption ok'
        True
        >>> str(result)
        'hello again'
        >>> result = gpg.encrypt("signed hello",print2,sign=print1,passphrase='foo')
        >>> result.status == 'encryption ok'
        True
        >>> message = str(result)
        >>> result = gpg.decrypt(message)
        >>> result.status == 'decryption ok'
        True
        >>> assert result.fingerprint == print1

        """
        data = util._make_binary_stream(data, self.encoding)
        result = self.encrypt_file(data, recipients, **kwargs)
        data.close()
        return result

    def decrypt(self, message, **kwargs):
        """Decrypt the contents of a string or file-like object ``message``.

        :param message: A string or file-like object to decrypt.
        """
        data = util._make_binary_stream(message, self.encoding)
        result = self.decrypt_file(data, **kwargs)
        data.close()
        return result

    def decrypt_file(self, file, always_trust=False, passphrase=None,
                     output=None):
        """
        Decrypt the contents of a file-like object :param:file .

        :param file: A file-like object to decrypt.
        :param always_trust: Instruct GnuPG to ignore trust checks.
        :param passphrase: The passphrase for the secret key used for decryption.
        :param output: A file to write the decrypted output to.
        """
        args = ["--decrypt"]
        if output:  # write the output to a file with the specified name
            if os.path.exists(output):
                os.remove(output) # to avoid overwrite confirmation message
            args.append('--output "%s"' % output)
        if always_trust:
            args.append("--always-trust")
        result = self._result_map['crypt'](self)
        self._handle_io(args, file, result, passphrase, binary=True)
        logger.debug('decrypt result: %r', result.data)
        return result


class GPGWrapper(GPG):
    """
    This is a temporary class for handling GPG requests, and should be
    replaced by a more general class used throughout the project.
    """

    def __init__(self, gpgbinary=None, gnupghome=_conf,
                 verbose=False, use_agent=False, keyring=None, options=None):
        super(GPGWrapper, self).__init__(gnupghome=gnupghome,
                                         gpgbinary=gpgbinary,
                                         verbose=verbose,
                                         use_agent=use_agent,
                                         keyring=keyring,
                                         options=options)
        self._result_map['list-packets'] = ListPackets

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
        """Send keys to a keyserver."""
        result = self._result_map['list'](self)
        gnupg.logger.debug('send_keys: %r', keyids)
        data = gnupg.util._make_binary_stream("", self.encoding)
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
            if not util._is_list_or_tuple(recipients):
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
        result = self._result_map['crypt'](self)
        self._handle_io(args, file, result, passphrase=passphrase, binary=True)
        logger.debug('encrypt result: %r', result.data)
        return result

    def list_packets(self, raw_data):
        args = ["--list-packets"]
        result = self._result_map['list-packets'](self)
        self._handle_io(args,
                        util._make_binary_stream(raw_data, self.encoding),
                        result)
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
