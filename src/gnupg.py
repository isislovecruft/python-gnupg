# -*- coding: utf-8 -*-
#
# This file is part of python-gnupg, a Python interface to GnuPG.
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
"""gnupg.py
========
A Python interface to GnuPG.

This is a modified version of python-gnupg-0.3.0, which was created by Vinay
Sajip, which itself is a modification of GPG.py written by Steve Traugott,
which in turn is a modification of the pycrypto GnuPG interface written by
A.M. Kuchling.

This version is patched to sanitize untrusted inputs, due to the necessity of
executing :class:`subprocess.Popen([...], shell=True)` in order to communicate
with GnuPG.

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

try:
    from io import StringIO
    from io import BytesIO
except ImportError:
    from cStringIO import StringIO

from pprint     import pprint
from psutil     import process_iter
from subprocess import Popen
from subprocess import PIPE

import atexit
import codecs
## For AOS, the locale module will need to point to a wrapper around the
## java.util.Locale class.
## See https://code.patternsinthevoid.net/?p=android-locale-hack.git
import locale
import logging
import os
import re
import socket
import sys
import tempfile
import threading

from _parsers import _fix_unsafe, _sanitise, _is_allowed, _sanitise_list
from _parsers import _check_preferences
from _util    import InheritableProperty
from _util    import _conf, _is_list_or_tuple, _is_stream
from _util    import _make_binary_stream
from _util    import log

import _util
import _parsers


class GPGMeta(type):
    """Metaclass for changing the :meth:GPG.__init__ initialiser.

    Detects running gpg-agent processes and the presence of a pinentry
    program, and disables pinentry so that python-gnupg can write the
    passphrase to the controlled GnuPG process without killing the agent.
    """

    def __new__(cls, name, bases, attrs):
        """Construct the initialiser for GPG"""
        log.debug("Metaclass __new__ constructor called for %r" % cls)
        if cls._find_agent():
            ## call the normal GPG.__init__() initialisor:
            attrs['init'] = cls.__init__ ## nothing changed for now
            attrs['_remove_agent'] = True
        return super(GPGMeta, cls).__new__(cls, name, bases, attrs)

    @classmethod
    def _find_agent(cls):
        """Discover if a gpg-agent process for the current euid is running.

        If there is a matching gpg-agent process, set a :class:psutil.Process
        instance containing the gpg-agent process' information to
        :attr:cls._agent_proc.

        :returns: True if there exists a gpg-agent process running under the
                  same effective user ID as that of this program. Otherwise,
                  returns None.
        """
        identity = os.getresuid()
        for proc in process_iter():
            if (proc.name == "gpg-agent") and proc.is_running:
                log.debug("Found gpg-agent process with pid %d" % proc.pid)
                if proc.uids == identity:
                    log.debug(
                        "Effective UIDs of this process and gpg-agent match")
                    setattr(cls, '_agent_proc', proc)
                    return True

    ## xxx we might not need this, try setting:
    ## attrs['remove_path'] = __remove_path__

    # @classmethod
    # def _init_decorator(cls):
    #     """Wraps the :meth:__init__ function in a partial of itself."""
    #     log.debug("_init_decorator called for %s" % cls.__init__.__repr__())
    #     def _init_wrapper(*args, **kwargs):
    #         wraps(cls.__init__, *args, **kwargs)
    #         if getattr(cls, '_agent_proc', None) is not None:
    #             cls.__remove_path__(prog='pinentry')
    #     return _init_wrapper


class GPGBase(object):
    """Base class to control process initialisation and for property storage."""

    __metaclass__  = GPGMeta

    def __init__(self, binary=None, home=None, keyring=None, secring=None,
                 use_agent=False, default_preference_list=None,
                 verbose=False, options=None):

        self.binary  = _util._find_binary(binary)
        self.homedir = home if home else _conf
        pub = _fix_unsafe(keyring) if keyring else 'pubring.gpg'
        sec = _fix_unsafe(secring) if secring else 'secring.gpg'
        self.keyring = os.path.join(self._homedir, pub)
        self.secring = os.path.join(self._homedir, sec)
        self._prefs  = 'SHA512 SHA384 SHA256 AES256 CAMELLIA256 TWOFISH ZLIB ZIP'
        self.options = _sanitise(options) if options else None

        self.encoding = locale.getpreferredencoding()
        if self.encoding is None: # This happens on Jython!
            self.encoding = sys.stdin.encoding

        try:
            assert self.binary, "Could not find binary %s" % binary
            assert isinstance(verbose, (bool, str, int)), \
                "'verbose' must be boolean, string, or 0 <= n <= 9"
            assert isinstance(use_agent, bool), "'use_agent' must be boolean"

            if self.options is not None:
                assert isinstance(self.options, str), "options not string"
        except (AssertionError, AttributeError) as ae:
            log.error("GPGBase.__init__(): %s" % ae.message)
            raise RuntimeError(ae.message)
        else:
            self.verbose = verbose
            self.use_agent = use_agent

        if hasattr(self, '_agent_proc') \
                and getattr(self, '_remove_agent', None) is True:
            if hasattr(self, '__remove_path__'):
                self.__remove_path__('pinentry')

    def __remove_path__(self, prog=None):
        log.debug("Attempting to remove %s from system PATH" % str(prog))
        if (prog is None) or (not isinstance(prog, str)): return

        try:
            program = _util._which(prog)[0]
        except (OSError, IOerror, IndexError) as err:
            log.err(err.message)
            log.err("Cannot find program '%s', not changing PATH." % prog)
            return

        ## __remove_path__ cannot be an @classmethod in GPGMeta, because
        ## the use_agent attribute must be set by the instance.
        if not self.use_agent:
            program_path = os.path.dirname(program)

            ## symlink our gpg binary into the current working directory
            if os.path.dirname(self.gpg.binary) == program_path:
                os.symlink(self.gpg.binary, os.path.join(os.getcwd(), 'gpg'))

            ## copy the original environment so we can put it back later:
            env_copy = os.environ
            path_copy = os.environ.pop('PATH')
            assert not os.environ.has_key('PATH')
            log.debug("Created a copy of system PATH: %r" % path_copy)

            path_string = '{}:'.format(program_path)
            rm_program = path_copy.replace(path_string, None)

            @staticmethod
            def update_path(env_copy, path_value):
                log.debug("Updating system path...")
                os.environ = env_copy
                os.environ.update({'PATH': path_value})
                log.debug("System $PATH: %s" % os.environ['PATH'])

            update_path(env_copy, rm_program)

            ## register an _exithandler with the python interpreter:
            atexit.register(update_path, env_copy, path_copy)

    # @property
    # def keyring(self):
    #     """Get the public keyring."""
    #     return self._keyring
    #
    # @keyring.setter
    # def keyring(self, pub):
    #     """Set the file to use as GnuPG's current (public) keyring.
    #
    #     :param str pub: The filename, relative to :attr:``GPG.homedir``, to use
    #                     for storing public key data.
    #     """
    #     ring = _fix_unsafe(pub) if pub else 'pubring.gpg'
    #     self._keyring = os.path.join(self._homedir, ring)
    #
    # @property
    # def secring(self):
    #     """Get the secret keyring."""
    #     return self._secring
    #
    # @secring.setter
    # def secring(self, sec):
    #     """Set the file to use as GnuPG's current secret keyring.
    #
    #     :param str pub: The filename, relative to :attr:``GPG.homedir``, to use
    #                     for storing secret key data.
    #     """
    #     ring = _fix_unsafe(sec) if sec else 'secring.gpg'
    #     self._secring = os.path.join(self._homedir, ring)

    @property
    def default_preference_list(self):
        """Get the default preference list."""
        return self._prefs

    @default_preference_list.setter
    def default_preference_list(self, prefs):
        """Set the default preference list.

        :param str prefs: A string containing the default preferences for
                          ciphers, digests, and compression algorithms.
        """
        prefs = _check_preferences(prefs)
        if prefs is not None:
            self._prefs = prefs

    @default_preference_list.deleter
    def default_preference_list(self, prefs):
        """Reset the default preference list to its original state.

        Note that "original state" does not mean the default preference
        list for whichever version of GnuPG is being used. It means the
        default preference list defined by :attr:`GPGBase._preferences`.

        Using BZIP2 is avoided due to not interacting well with some versions
        of GnuPG>=2.0.0.
        """
        self._prefs = 'SHA512 SHA384 SHA256 AES256 CAMELLIA256 TWOFISH ZLIB ZIP'


    def _homedir_getter(self):
        """Get the directory currently being used as GnuPG's homedir.

        If unspecified, use $HOME/.config/python-gnupg/

        :rtype: str
        :returns: The absolute path to the current GnuPG homedir.
        """
        return self._homedir

    def _homedir_setter(self, directory):
        """Set the directory to use as GnuPG's homedir.

        If unspecified, use $HOME/.config/python-gnupg. If specified, ensure
        that the ``directory`` does not contain various shell escape
        characters. If ``directory`` is not found, it will be automatically
        created. Lastly, the ``direcory`` will be checked that the EUID has
        read and write permissions for it.

        :param str homedir: A relative or absolute path to the directory to use
                            for storing/accessing GnuPG's files, including
                            keyrings and the trustdb.
        :raises: :exc:`RuntimeError` if unable to find a suitable directory to
                 use.
        """
        if not directory:
            log.debug("GPGBase._homedir_setter(): Using default homedir: '%s'"
                         % _conf)
            directory = _conf

        hd = _fix_unsafe(directory)
        log.debug("GPGBase._homedir_setter(): got directory '%s'" % hd)

        if hd:
            log.debug("GPGBase._homedir_setter(): Check existence of '%s'" % hd)
            _util._create_if_necessary(hd)

        try:
            log.debug("GPGBase._homedir_setter(): checking permissions")
            assert _util._has_readwrite(hd), \
                "Homedir '%s' needs read/write permissions" % hd
        except AssertionError as ae:
            msg = ("Unable to set '%s' as GnuPG homedir" % directory)
            log.debug("GPGBase.homedir.setter(): %s" % msg)
            log.debug(ae.message)
            raise RuntimeError(ae.message)
        else:
            log.debug("GPGBase:")
            log.info("Setting homedir to '%s'" % hd)
            self._homedir = hd

    homedir = InheritableProperty(_homedir_getter, _homedir_setter)


class GPG(GPGBase):
    """Encapsulate access to the gpg executable"""

    _decode_errors = 'strict'
    _result_map    = { 'crypt':    _parsers.Crypt,
                       'delete':   _parsers.DeleteResult,
                       'generate': _parsers.GenKey,
                       'import':   _parsers.ImportResult,
                       'list':     _parsers.ListKeys,
                       'sign':     _parsers.Sign,
                       'verify':   _parsers.Verify,
                       'packets':  _parsers.ListPackets }

    def __init__(self, binary=None, homedir=None, verbose=False,
                 use_agent=False, keyring=None, secring=None,
                 default_preference_list=None, options=None):
        """Initialize a GnuPG process wrapper.

        :param str binary: Name for GnuPG binary executable. If the absolute
                           path is not given, the evironment variable $PATH is
                           searched for the executable and checked that the
                           real uid/gid of the user has sufficient permissions.

        :param str homedir: Full pathname to directory containing the public
                            and private keyrings. Default is whatever GnuPG
                            defaults to.

        :param str keyring: Name of keyring file containing public key data, if
                            unspecified, defaults to 'pubring.gpg' in the
                            ``homedir`` directory.

        :param str secring: Name of alternative secret keyring file to use. If
                            left unspecified, this will default to using
                            'secring.gpg' in the :param:homedir directory, and
                            create that file if it does not exist.

        :param str pubring: Name of alternative public keyring file to use. If
                            left unspecified, this will default to using
                            'pubring.gpg' in the :param:homedir directory, and
                            create that file if it does not exist.

        :param list options: A list of additional options to pass to the GPG
                             binary.

        :raises: :exc:`RuntimeError` with explanation message if there is a
                 problem invoking gpg.
        """

        if not homedir:
            homedir = _conf
        self.homedir = _fix_unsafe(homedir)
        if self.homedir:
            _util._create_homedir(self.homedir)
        else:
            message = ("Unsuitable gpg home dir: %s" % homedir)
            log.debug("GPG.__init__(): %s" % message)

        self.binary = _util._find_binary(binary)

        if default_preference_list is None:
            prefs = 'SHA512 SHA384 SHA256 AES256 CAMELLIA256 TWOFISH ZLIB ZIP'
        else:
            prefs = _check_preferences(default_preference_list)
        self.default_preference_list = prefs

        secring = 'secring.gpg' if secring is None else _fix_unsafe(secring)
        keyring = 'pubring.gpg' if keyring is None else _fix_unsafe(keyring)
        self.secring = os.path.join(self.homedir, secring)
        self.keyring = os.path.join(self.homedir, keyring)

        self.options = _sanitise(options) if options else None

        self.encoding = locale.getpreferredencoding()
        if self.encoding is None: # This happens on Jython!
            self.encoding = sys.stdin.encoding

        try:
            assert self.homedir is not None, "Got None for self.homedir"
            assert _util._has_readwrite(self.homedir), ("Home dir %s needs r+w"
                                                       % self.homedir)
            assert self.binary, "Could not find binary %s" % full
            assert isinstance(verbose, bool), "'verbose' must be boolean"
            assert isinstance(use_agent, bool), "'use_agent' must be boolean"
            if self.options:
                assert isinstance(options, str), ("options not formatted: %s"
                                                  % options)
        except (AssertionError, AttributeError) as ae:
            log.debug("GPG.__init__(): %s" % ae.message)
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
        ## see TODO file, tag :io:makeargs:
        cmd = [self.binary, '--no-emit-version --no-tty --status-fd 2']

        if self.homedir:
            cmd.append('--homedir "%s"' % self.homedir)
        if self.keyring:
            cmd.append('--no-default-keyring --keyring %s' % self.keyring)
            if self.secring:
                cmd.append('--secret-keyring %s' % self.secring)
        if passphrase:
            cmd.append('--batch --passphrase-fd 0')
        if self.use_agent:
            cmd.append('--use-agent')
        else:
            cmd.append('--no-use-agent')
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
        log.debug("_open_subprocess(): %s", cmd)
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
                log.info("%s" % line)
            else:
                log.debug("%s" % line)
            if line[0:9] == '[GNUPG:] ':
                # Chop off the prefix
                line = line[9:]
                L = line.split(None, 1)
                keyword = L[0]
                if len(L) > 1:
                    value = L[1]
                else:
                    value = ""
                result._handle_status(keyword, value)
        result.stderr = ''.join(lines)

    def _read_data(self, stream, result):
        """Read the contents of the file from GPG's stdout."""
        chunks = []
        while True:
            data = stream.read(1024)
            if len(data) == 0:
                break
            log.debug("GPG._read_data(): read chunk: %r" % data[:256])
            chunks.append(data)
        if _util._py3k:
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
        log.debug('GPG._collect_output(): stderr reader: %r', rr)
        rr.start()

        stdout = process.stdout
        dr = threading.Thread(target=self._read_data, args=(stdout, result))
        dr.setDaemon(True)
        log.debug('GPG._collect_output(): stdout reader: %r', dr)
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
            _util._write_passphrase(stdin, passphrase, self.encoding)
        writer = _util._threaded_copy_data(file, stdin)
        self._collect_output(p, result, writer, stdin)
        return result

    def sign(self, message, **kwargs):
        """Create a signature for a message or file."""
        if isinstance(message, file):
            if 'keyid' in kwargs.items():
                log.info("Signing file '%r' with keyid: %s"
                         % (data, kwargs[keyid]))
            else:
                log.warn("No 'sign_with' keyid given! Using default key.")
            result = self._sign_file(message, **kwargs)
        elif not _util._is_stream(message):
            if 'keyid' in kwargs.items():
                log.info("Signing data string '%s' with keyid: %s"
                         % (data, kwargs[keyid]))
            else:
                log.warn("No 'sign_with' keyid given! Using default key.")
            f = _util._make_binary_stream(message, self.encoding)
            result = self._sign_file(f, **kwargs)
            f.close()
        else:
            log.warn("Unable to sign message '%s' with type %s"
                     % (data, type(data)))
            result = None
        return result

    def _sign_file(self, file, keyid=None, passphrase=None, clearsign=True,
                   detach=False, binary=False):
        """Create a signature for a  file."""
        log.debug("_sign_file():")
        if binary:
            log.info("Creating binary signature for file %s" % file)
            args = ['--sign']
        else:
            log.info("Creating ascii-armoured signature for file %s" % file)
            args = ['--sign --armor']

        if clearsign:
            args.append("--clearsign")
            if detach:
                log.warn("Cannot use both --clearsign and --detach-sign.")
                log.warn("Using default GPG behaviour: --clearsign only.")
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
                _util._write_passphrase(stdin, passphrase, self.encoding)
            writer = _util._threaded_copy_data(file, stdin)
        except IOError:
            log.exception("_sign_file(): Error writing message")
            writer = None
        self._collect_output(p, result, writer, stdin)
        return result

    def verify(self, data):
        """Verify the signature on the contents of the string ``data``.

        >>> gpg = GPG(homedir="keys")
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
        f = _util._make_binary_stream(data, self.encoding)
        result = self.verify_file(f)
        f.close()
        return result

    def verify_file(self, file, sig_file=None):
        """Verify the signature on the contents of a file or file-like
        object. Can handle embedded signatures as well as detached
        signatures. If using detached signatures, the file containing the
        detached signature should be specified as the ``sig_file``.

        :param file file: A file descriptor object. Its type will be checked
                          with :func:`_util._is_file`.
        :param str sig_file: A file containing the GPG signature data for
                             ``file``. If given, ``file`` is verified via this
                             detached signature.
        """

        fn = None
        result = self._result_map['verify'](self)

        if sig_file is None:
            log.debug("verify_file(): Handling embedded signature")
            args = ["--verify"]
            proc = self._open_subprocess(args)
            writer = _util._threaded_copy_data(file, proc.stdin)
            self._collect_output(proc, result, writer, stdin=proc.stdin)
        else:
            if not _util._is_file(sig_file):
                log.debug("verify_file(): '%r' is not a file" % sig_file)
                return result
            log.debug('verify_file(): Handling detached verification')
            sig_fh = None
            try:
                sig_fh = open(sig_file)
                args = ["--verify %s - " % sig_fh.name]
                proc = self._open_subprocess(args)
                writer = _util._threaded_copy_data(file, proc.stdin)
                self._collect_output(proc, result, stdin=proc.stdin)
            finally:
                if sig_fh and not sig_fh.closed:
                    sig_fh.close()
        return result

    def import_keys(self, key_data):
        """
        Import the key_data into our keyring.

        >>> import shutil
        >>> shutil.rmtree("keys")
        >>> gpg = GPG(homedir="keys")
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
        log.debug('import_keys: %r', key_data[:256])
        data = _util._make_binary_stream(key_data, self.encoding)
        self._handle_io(['--import'], data, result, binary=True)
        log.debug('import_keys result: %r', result.__dict__)
        data.close()
        return result

    def recv_keys(self, keyserver, *keyids):
        """Import a key from a keyserver

        >>> import shutil
        >>> shutil.rmtree("keys")
        >>> gpg = GPG(homedir="keys")
        >>> result = gpg.recv_keys('pgp.mit.edu', '3FF0DB166A7476EA')
        >>> assert result

        """
        safe_keyserver = _fix_unsafe(keyserver)

        result = self._result_map['import'](self)
        data = _util._make_binary_stream("", self.encoding)
        args = ['--keyserver', keyserver, '--recv-keys']

        if keyids:
            if keyids is not None:
                safe_keyids = ' '.join(
                    [(lambda: _fix_unsafe(k))() for k in keyids])
                log.debug('recv_keys: %r', safe_keyids)
                args.extend(safe_keyids)

        self._handle_io(args, data, result, binary=True)
        data.close()
        log.debug('recv_keys result: %r', result.__dict__)
        return result

    def delete_keys(self, fingerprints, secret=False, subkeys=False):
        """Delete a key, or list of keys, from the current keyring.

        The keys must be refered to by their full fingerprint for GnuPG to
        delete them. If :param:`secret <secret=True>`, the corresponding secret
        keyring will be deleted from :attr:`GPG.secring <self.secring>`.

        :type fingerprints: str or list or tuple
        :param fingerprints: A string representing the fingerprint (or a
                             list/tuple of fingerprint strings) for the key(s)
                             to delete.

        :param bool secret: If True, delete the corresponding secret key(s)
                            also. (default: False)
        :param bool subkeys: If True, delete the secret subkey first, then
                             the public key. Same as
                            ``gpg --delete-secret-and-public-key 0x12345678``
                            (default: False)
        """

        which='keys'
        if secret:
            which='secret-key'
        if subkeys:
            which='secret-and-public-key'

        if _util._is_list_or_tuple(fingerprints):
            fingerprints = ' '.join(fingerprints)

        args = ['--batch']
        args.append("--delete-{} {}".format(which, fingerprints))

        result = self._result_map['delete'](self)
        p = self._open_subprocess(args)
        self._collect_output(p, result, stdin=p.stdin)
        return result

    def export_keys(self, keyids, secret=False, subkeys=False):
        """Export the indicated ``keyids``.

        :param str keyids: A keyid or fingerprint in any format that GnuPG will
                           accept.
        :param bool secret: If True, export only the secret key.
        :param bool subkeys: If True, export the secret subkeys.
        """
        which=''
        if subkeys:
            which='-secret-subkeys'
        elif secret:
            which='-secret-keys'

        if _util._is_list_or_tuple(keyids):
            keyids = ' '.join(['%s' % k for k in keyids])

        args = ["--armor"]
        args.append("--export{} {}".format(which, keyids))

        p = self._open_subprocess(args)
        ## gpg --export produces no status-fd output; stdout will be empty in
        ## case of failure
        #stdout, stderr = p.communicate()
        result = self._result_map['delete'](self) # any result will do
        self._collect_output(p, result, stdin=p.stdin)
        log.debug('export_keys result: %r', result.data)
        return result.data.decode(self.encoding, self._decode_errors)

    def list_keys(self, secret=False):
        """List the keys currently in the keyring.

        >>> import shutil
        >>> shutil.rmtree("keys")
        >>> gpg = GPG(homedir="keys")
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
        args = "--list-%s --fixed-list-mode --fingerprint " % (which,)
        args += "--with-colons --list-options no-show-photos"
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
            log.debug("line: %r", line.rstrip())
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
        raise NotImplemented("Functionality for '--list-sigs' not implemented.")

    def gen_key(self, input):
        """Generate a GnuPG key through batch file key generation. See
        :meth:`GPG.gen_key_input()` for creating the control input.

        >>> gpg = GPG(homedir="keys")
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
        ## see TODO file, tag :gen_key: for todo items
        args = ["--gen-key --batch"]
        key = self._result_map['generate'](self)
        f = _util._make_binary_stream(input, self.encoding)
        self._handle_io(args, f, key, binary=True)
        f.close()
        return key

    def gen_key_input(self, testing=False, **kwargs):
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

        >>> gpg = GPG(homedir="keys")
        >>> params = {'name_real':'python-gnupg tester', 'name_email':'test@ing'}
        >>> key_input = gpg.gen_key_input(**params)
        >>> result = gpg.gen_key(input)
        >>> assert result

        :param bool testing: Uses a faster, albeit insecure random number
                             generator to create keys. This should only be used
                             for testing purposes, for keys which are going to
                             be created and then soon after destroyed, and
                             never for the generation of actual use keys.

        :param str name_real: The name portion of the UID of the generated key.
        :param str name_comment: The comment in the UID of the generated key.
        :param str name_email: The email in the UID of the generated key.
                               (default: $USER@$(hostname) ) Remember to use
                               UTF-8 encoding for the entirety of the UID. At
                               least one of :param:`name_real <name_real>`,
                               :param:`name_comment <name_comment>`, or
                               :param:`name_email <name_email>` must be
                               provided, or else no user ID is created.

        :param str key_type: One of 'RSA', 'DSA', or 'ELG-E'. (default: 'RSA')
                             Starts a new parameter block by giving the type of
                             the primary key. The algorithm must be capable of
                             signing. This is a required parameter. The
                             algorithm may either be an OpenPGP algorithm
                             number or a string with the algorithm name. The
                             special value ‘default’ may be used for algo to
                             create the default key type; in this case a
                             :param:`key_usage <key_usage>` should not be given
                             and ‘default’ must also be used for
                             :param:`subkey_type <subkey_type>`.

        :param int key_length: The requested length of the generated key in
                               bits. (Default: 4096)

        :param str key_grip: hexstring This is an optional hexidecimal string
                             which is used to generate a CSR or certificate for
                             an already existing key. :param:key_length
                             will be ignored if this parameter is given.

        :param str key_usage: Space or comma delimited string of key
                              usages. Allowed values are ‘encrypt’, ‘sign’, and
                              ‘auth’. This is used to generate the key
                              flags. Please make sure that the algorithm is
                              capable of this usage. Note that OpenPGP requires
                              that all primary keys are capable of
                              certification, so no matter what usage is given
                              here, the ‘cert’ flag will be on. If no
                              ‘Key-Usage’ is specified and the ‘Key-Type’ is
                              not ‘default’, all allowed usages for that
                              particular algorithm are used; if it is not given
                              but ‘default’ is used the usage will be ‘sign’.

        :param str subkey_type: This generates a secondary key
                                (subkey). Currently only one subkey can be
                                handled. See also ``key_type`` above.

        :param int subkey_length: The length of the secondary subkey in bits.

        :param str subkey_usage: Key usage for a subkey; similar to
                                 ``key_usage``.

        :type expire_date: int or str
        :param expire_date: Can be specified as an iso-date or as
                            <int>[d|w|m|y] Set the expiration date for the key
                            (and the subkey). It may either be entered in ISO
                            date format (2000-08-15) or as number of days,
                            weeks, month or years. The special notation
                            "seconds=N" is also allowed to directly give an
                            Epoch value. Without a letter days are
                            assumed. Note that there is no check done on the
                            overflow of the type used by OpenPGP for
                            timestamps. Thus you better make sure that the
                            given value make sense. Although OpenPGP works with
                            time intervals, GnuPG uses an absolute value
                            internally and thus the last year we can represent
                            is 2105.

        :param str creation_date: Set the creation date of the key as stored in
                                  the key information and which is also part of
                                  the fingerprint calculation. Either a date
                                  like "1986-04-26" or a full timestamp like
                                  "19860426T042640" may be used. The time is
                                  considered to be UTC. If it is not given the
                                  current time is used.

        :param str passphrase: The passphrase for the new key. The default is
                               to not use any passphrase. Note that
                               GnuPG>=2.1.x will not allow you to specify a
                               passphrase for batch key generation -- GnuPG
                               will ignore the ``passphrase`` parameter, stop,
                               and ask the user for the new passphrase.
                               However, we can put the command '%no-protection'
                               into the batch key generation file to allow a
                               passwordless key to be created, which can then
                               have its passphrase set later with '--edit-key'.

        :param str preferences: Set the cipher, hash, and compression
                                preference values for this key. This expects
                                the same type of string as the sub-command
                                ‘setpref’ in the --edit-key menu.

        :param str revoker: Should be given as 'algo:fpr' [case sensitive].
                            Add a designated revoker to the generated key. Algo
                            is the public key algorithm of the designated
                            revoker (i.e. RSA=1, DSA=17, etc.) fpr is the
                            fingerprint of the designated revoker. The optional
                            ‘sensitive’ flag marks the designated revoker as
                            sensitive information. Only v4 keys may be
                            designated revokers.

        :param str keyserver: This is an optional parameter that specifies the
                              preferred keyserver URL for the key.

        :param str handle: This is an optional parameter only used with the
                           status lines KEY_CREATED and KEY_NOT_CREATED. string
                           may be up to 100 characters and should not contain
                           spaces. It is useful for batch key generation to
                           associate a key parameter block with a status line.

        :rtype: str
        :returns: A suitable input string for the ``GPG.gen_key()`` method, the
                  latter of which will create the new keypair.

        see http://www.gnupg.org/documentation/manuals/gnupg-devel/Unattended-GPG-key-generation.html#Unattended-GPG-key-generation
        for more details.
        """

        parms = {}

        for key, val in list(kwargs.items()):
            key = key.replace('_','-').title()
            if str(val).strip():    # skip empty strings
                parms[key] = val

        parms.setdefault('Key-Type', 'RSA')
        parms.setdefault('Key-Length', 4096)
        parms.setdefault('Name-Real', "Autogenerated Key")
        parms.setdefault('Expire-Date', _util._next_year())

        try:
            logname = os.environ['LOGNAME']
        except KeyError:
            logname = os.environ['USERNAME']
        hostname = socket.gethostname()

        parms.setdefault('Name-Email', "%s@%s" % (logname.replace(' ', '_'),
                                                  hostname))

        if testing:
            ## This specific comment string is required by (some? all?)
            ## versions of GnuPG to use the insecure PRNG:
            parms.setdefault('Name-Comment', 'insecure!')

        out = "Key-Type: %s\n" % parms.pop('Key-Type')

        for key, val in list(parms.items()):
            out += "%s: %s\n" % (key, val)

        out += "%%pubring %s\n" % self.keyring
        out += "%%secring %s\n" % self.secring

        if testing:
            ## see TODO file, tag :compatibility:gen_key_input:
            ##
            ## Add version detection before the '%no-protection' flag.
            out += "%no-protection\n"
            out += "%transient-key\n"

        out += "%commit\n"
        return out

    #
    # ENCRYPTION
    #
    def encrypt_file(self, file, recipients, sign_with=None,
                     always_trust=False, passphrase=None, armor=True,
                     output=None, encrypt=True, symmetric=False,
                     cipher_algo='AES256', digest_algo='SHA512',
                     compress_algo='ZLIB'):
        """Encrypt the message read from ``file``.

        :type file: file or :class:BytesIO
        :param file: The file or bytestream to encrypt.
        :type recipients: str or list or tuple
        :param recipients: The recipients to encrypt to. Recipients may be
                           specified by UID or keyID/fingerprint.
        :param str sign_with: The keyID to use for signing, i.e.
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
        """

        args = list()

        ## both can be used at the same time for an encrypted file which
        ## is decryptable with a passphrase or secretkey.
        if encrypt:
            args.append('--encrypt')
        if symmetric:
            args.append('--symmetric')

        if not _util._is_list_or_tuple(recipients):
            if isinstance(recipients, str):
                recipients = [rec for rec in recipients.split(' ')]
            else:
                recipients = (recipients,)
        if len(recipients) > 1:
            args.append('--multifile')
        for recipient in recipients:
            args.append('--recipient %s' % recipient)

        if output is not None:
            if getattr(output, 'fileno', None) is not None:
                if os.path.exists(output):
                    os.remove(output) # to avoid overwrite confirmation message
            args.append('--output "%s"' % output)

        if armor:
            args.append('--armor')
        if sign_with:
            args.append('--sign')
            args.append('--default-key %s' % sign_with)
            if digest_algo:
                args.append('--digest-algo %s' % digest_algo)
        if always_trust:
            args.append('--always-trust')

        if cipher_algo:
            args.append('--cipher-algo %s' % cipher_algo)
        if compress_algo:
            args.append('--compress-algo %s' % compress_algo)

        result = self._result_map['crypt'](self)
        self._handle_io(args, file, result, passphrase=passphrase, binary=True)
        log.debug('GPG.encrypt(): Result: %r', result.data)
        return result

    def encrypt(self, data, recipients, **kwargs):
        """Encrypt the message contained in ``data`` to ``recipients``.

        >>> import shutil
        >>> if os.path.exists("keys"):
        ...     shutil.rmtree("keys")
        >>> gpg = GPG(homedir="keys")
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
        data = _util._make_binary_stream(data, self.encoding)
        result = self.encrypt_file(data, recipients, **kwargs)
        data.close()
        return result

    def decrypt(self, message, **kwargs):
        """Decrypt the contents of a string or file-like object ``message``.

        :param message: A string or file-like object to decrypt.
        """
        data = _util._make_binary_stream(message, self.encoding)
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
        log.debug('decrypt result: %r', result.data)
        return result


class GPGWrapper(GPG):
    """
    This is a temporary class for handling GPG requests, and should be
    replaced by a more general class used throughout the project.
    """

    def __init__(self, binary=None, homedir=_conf,
                 verbose=False, use_agent=False, keyring=None, options=None):
        super(GPGWrapper, self).__init__(gnupghome=gnupghome,
                                         binary=binary,
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

    def encrypt(self, data, recipient, sign_with=None, always_trust=True,
                passphrase=None, symmetric=False):
        """
        Encrypt data using GPG.
        """
        # TODO: devise a way so we don't need to "always trust".
        return super(GPGWrapper, self).encrypt(data, recipient,
                                               sign_with=sign,
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
        log.debug('send_keys: %r', keyids)
        data = _util._make_binary_stream("", self.encoding)
        args = ['--keyserver', keyserver, '--send-keys']
        args.extend(keyids)
        self._handle_io(args, data, result, binary=True)
        log.debug('send_keys result: %r', result.__dict__)
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
            if not _util._is_list_or_tuple(recipients):
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
        log.debug('encrypt result: %r', result.data)
        return result

    def list_packets(self, raw_data):
        args = ["--list-packets"]
        result = self._result_map['list-packets'](self)
        self._handle_io(args,
                        _util._make_binary_stream(raw_data, self.encoding),
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
