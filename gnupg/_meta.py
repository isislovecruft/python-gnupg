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

'''meta.py
----------
Meta and base classes for hiding internal functions, and controlling attribute
creation and handling.
'''

from __future__ import absolute_import

import atexit
import codecs
import encodings
## For AOS, the locale module will need to point to a wrapper around the
## java.util.Locale class.
## See https://code.patternsinthevoid.net/?p=android-locale-hack.git
import locale
import os
import psutil
import subprocess
import sys
import threading

from . import _parsers
from . import _util

from ._parsers import _check_preferences
from ._parsers import _sanitise_list
from ._util    import log


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
            ## call the normal GPG.__init__() initialiser:
            attrs['init'] = cls.__init__
            attrs['_remove_agent'] = True
        return super(GPGMeta, cls).__new__(cls, name, bases, attrs)

    @classmethod
    def _find_agent(cls):
        """Discover if a gpg-agent process for the current euid is running.

        If there is a matching gpg-agent process, set a :class:`psutil.Process`
        instance containing the gpg-agent process' information to
        :attr:`GPG._agent_proc`.

        :returns: True if there exists a gpg-agent process running under the
                  same effective user ID as that of this program. Otherwise,
                  returns None.
        """
        identity = os.getresuid()
        for proc in psutil.process_iter():
            if (proc.name == "gpg-agent") and proc.is_running:
                log.debug("Found gpg-agent process with pid %d" % proc.pid)
                if proc.uids == identity:
                    log.debug(
                        "Effective UIDs of this process and gpg-agent match")
                    setattr(cls, '_agent_proc', proc)
                    return True


class GPGBase(object):
    """Base class for property storage and to control process initialisation."""

    __metaclass__  = GPGMeta

    _decode_errors = 'strict'
    _result_map    = { 'crypt':    _parsers.Crypt,
                       'delete':   _parsers.DeleteResult,
                       'generate': _parsers.GenKey,
                       'import':   _parsers.ImportResult,
                       'list':     _parsers.ListKeys,
                       'sign':     _parsers.Sign,
                       'verify':   _parsers.Verify,
                       'packets':  _parsers.ListPackets }

    def __init__(self, binary=None, home=None, keyring=None, secring=None,
                 use_agent=False, default_preference_list=None,
                 verbose=False, options=None):

        self.binary  = _util._find_binary(binary)
        self.homedir = home if home else _util._conf
        pub = _parsers._fix_unsafe(keyring) if keyring else 'pubring.gpg'
        sec = _parsers._fix_unsafe(secring) if secring else 'secring.gpg'
        self.keyring = os.path.join(self._homedir, pub)
        self.secring = os.path.join(self._homedir, sec)
        self.options = _parsers._sanitise(options) if options else None

        if default_preference_list:
            self._prefs = _check_preferences(default_preference_list, 'all')
        else:
            self._prefs  = 'SHA512 SHA384 SHA256 AES256 CAMELLIA256 TWOFISH'
            self._prefs += ' AES192 ZLIB ZIP Uncompressed'

        encoding = locale.getpreferredencoding()
        if encoding is None: # This happens on Jython!
            encoding = sys.stdin.encoding
        self._encoding = encoding.lower().replace('-', '_')
        self._filesystemencoding = encodings.normalize_encoding(
            sys.getfilesystemencoding().lower())

        self._keyserver = 'hkp://subkeys.pgp.net'
        self.__generated_keys = os.path.join(self.homedir, 'generated-keys')

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

    def __remove_path__(self, prog=None, at_exit=True):
        """Remove a the directories containing a program from the system's
        ``$PATH``. If :attr:`GPG.binary` is in a directory being removed, it
        is symlinked to './gpg'

        :param str prog: The program to remove from ``$PATH``.

        :param bool at_exit: Add the program back into the ``$PATH`` when the
                             Python interpreter exits, and delete any symlinks
                             to :attr:`GPG.binary` which were created.
        """
        #: A list of ``$PATH`` entries which were removed to disable pinentry.
        self._removed_path_entries = []

        log.debug("Attempting to remove %s from system PATH" % str(prog))
        if (prog is None) or (not isinstance(prog, str)): return

        try:
            program = _util._which(prog)[0]
        except (OSError, IOError, IndexError) as err:
            log.err(err.message)
            log.err("Cannot find program '%s', not changing PATH." % prog)
            return

        ## __remove_path__ cannot be an @classmethod in GPGMeta, because
        ## the use_agent attribute must be set by the instance.
        if not self.use_agent:
            program_base = os.path.dirname(prog)
            gnupg_base = os.path.dirname(self.binary)

            ## symlink our gpg binary into $PWD if the path we are removing is
            ## the one which contains our gpg executable:
            new_gpg_location = os.path.join(os.getcwd(), 'gpg')
            if gnupg_base == program_base:
                os.symlink(self.binary, new_gpg_location)
                self.binary = new_gpg_location

            ## copy the original environment so that we can put it back later:
            env_copy = os.environ            ## this one should not be touched
            path_copy = os.environ.pop('PATH')
            log.debug("Created a copy of system PATH: %r" % path_copy)
            assert not os.environ.has_key('PATH'), "OS env kept $PATH anyway!"

            @staticmethod
            def remove_program_from_path(path, prog_base):
                """Remove all directories which contain a program from PATH.

                :param str path: The contents of the system environment's
                                 ``$PATH``.

                :param str prog_base: The directory portion of a program's
                                      location, without the trailing slash,
                                      and without the program name. For
                                      example, ``prog_base='/usr/bin'``.
                """
                paths = path.split(':')
                for directory in paths:
                    if directory == prog_base:
                        log.debug("Found directory with target program: %s"
                                  % directory)
                        path.remove(directory)
                        self._removed_path_entries.append(directory)
                log.debug("Deleted all found instance of %s." % directory)
                log.debug("PATH is now:%s%s" % (os.linesep, path))
                new_path = ':'.join([p for p in path])
                return new_path

            @staticmethod
            def update_path(environment, path):
                """Add paths to the string at os.environ['PATH'].

                :param str environment: The environment mapping to update.
                :param list path: A list of strings to update the PATH with.
                """
                log.debug("Updating system path...")
                os.environ = environment
                new_path = ':'.join([p for p in path])
                old = ''
                if 'PATH' in os.environ:
                    new_path = ':'.join([os.environ['PATH'], new_path])
                os.environ.update({'PATH': new_path})
                log.debug("System $PATH: %s" % os.environ['PATH'])

            modified_path = remove_program_from_path(path_copy, program_base)
            update_path(env_copy, modified_path)

            ## register an _exithandler with the python interpreter:
            atexit.register(update_path, env_copy, path_copy)

            def remove_symlinked_binary(symlink):
                if os.path.islink(symlink):
                    os.unlink(symlink)
                    log.debug("Removed binary symlink '%s'" % symlink)
            atexit.register(remove_symlinked_binary, new_gpg_location)

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
    def default_preference_list(self):
        """Reset the default preference list to its original state.

        Note that "original state" does not mean the default preference
        list for whichever version of GnuPG is being used. It means the
        default preference list defined by :attr:`GPGBase._preferences`.

        Using BZIP2 is avoided due to not interacting well with some versions
        of GnuPG>=2.0.0.
        """
        self._prefs = 'SHA512 SHA384 SHA256 AES256 CAMELLIA256 TWOFISH ZLIB ZIP'

    @property
    def keyserver(self):
        """Get the current keyserver setting."""
        return self._keyserver

    @keyserver.setter
    def keyserver(self, location):
        """Set the default keyserver to use for sending and receiving keys.

        The ``location`` is sent to :func:`_parsers._check_keyserver` when
        option are parsed in :meth:`gnupg.GPG._make_options`.

        :param str location: A string containing the default keyserver. This
                             should contain the desired keyserver protocol
                             which is supported by the keyserver, for example,
                             ``'hkps://keys.mayfirst.org'``. The default
                             keyserver is ``'hkp://subkeys.pgp.net'``.
        """
        self._keyserver = location

    @keyserver.deleter
    def keyserver(self):
        """Reset the keyserver to the default setting."""
        self._keyserver = 'hkp://subkeys.pgp.net'

    def _homedir_getter(self):
        """Get the directory currently being used as GnuPG's homedir.

        If unspecified, use :file:`~/.config/python-gnupg/`

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
                      % _util._conf)
            directory = _util._conf

        hd = _parsers._fix_unsafe(directory)
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
            log.info("Setting homedir to '%s'" % hd)
            self._homedir = hd

    homedir = _util.InheritableProperty(_homedir_getter, _homedir_setter)

    def _generated_keys_getter(self):
        """Get the ``homedir`` subdirectory for storing generated keys.

        :rtype: str
        :returns: The absolute path to the current GnuPG homedir.
        """
        return self.__generated_keys

    def _generated_keys_setter(self, directory):
        """Set the directory for storing generated keys.

        If unspecified, use $GNUPGHOME/generated-keys. If specified, ensure
        that the ``directory`` does not contain various shell escape
        characters. If ``directory`` is not found, it will be automatically
        created. Lastly, the ``direcory`` will be checked that the EUID has
        read and write permissions for it.

        :param str directory: A relative or absolute path to the directory to
             use for storing/accessing GnuPG's files, including keyrings and
             the trustdb.
        :raises: :exc:`RuntimeError` if unable to find a suitable directory to
             use.
        """
        if not directory:
            directory = os.path.join(self.homedir, 'generated-keys')
            log.debug("GPGBase._generated_keys_setter(): Using '%s'"
                      % directory)

        hd = _parsers._fix_unsafe(directory)
        log.debug("GPGBase._generated_keys_setter(): got directory '%s'" % hd)

        if hd:
            log.debug("GPGBase._generated_keys_setter(): Check exists '%s'"
                      % hd)
            _util._create_if_necessary(hd)

        try:
            log.debug("GPGBase._generated_keys_setter(): check permissions")
            assert _util._has_readwrite(hd), \
                "Keys dir '%s' needs read/write permissions" % hd
        except AssertionError as ae:
            msg = ("Unable to set '%s' as generated keys dir" % directory)
            log.debug("GPGBase._generated_keys_setter(): %s" % msg)
            log.debug(ae.message)
            raise RuntimeError(ae.message)
        else:
            log.info("Setting homedir to '%s'" % hd)
            self.__generated_keys = hd

    _generated_keys = _util.InheritableProperty(_generated_keys_getter,
                                                _generated_keys_setter)

    def _make_args(self, args, passphrase=False):
        """Make a list of command line elements for GPG. The value of ``args``
        will be appended only if it passes the checks in
        :func:`parsers._sanitise`. The ``passphrase`` argument needs to be True
        if a passphrase will be sent to GPG, else False.

        :param list args: A list of strings of options and flags to pass to
                          ``GPG.binary``. This is input safe, meaning that
                          these values go through strict checks (see
                          ``parsers._sanitise_list``) before being passed to to
                          the input file descriptor for the GnuPG process.
                          Each string should be given exactly as it would be on
                          the commandline interface to GnuPG,
                          e.g. ["--cipher-algo AES256", "--default-key
                          A3ADB67A2CDB8B35"].

        :param bool passphrase: If True, the passphrase will be sent to the
                                stdin file descriptor for the attached GnuPG
                                process.
        """
        ## see TODO file, tag :io:makeargs:
        cmd = [self.binary,
               '--no-options --no-emit-version --no-tty --status-fd 2']

        if self.homedir: cmd.append('--homedir "%s"' % self.homedir)

        if self.keyring:
            cmd.append('--no-default-keyring --keyring %s' % self.keyring)
        if self.secring:
            cmd.append('--secret-keyring %s' % self.secring)

        if passphrase: cmd.append('--batch --passphrase-fd 0')

        if self.use_agent: cmd.append('--use-agent')
        else: cmd.append('--no-use-agent')

        if self.options:
            [cmd.append(opt) for opt in iter(_sanitise_list(self.options))]
        if args:
            [cmd.append(arg) for arg in iter(_sanitise_list(args))]

        if self.verbose:
            cmd.append('--debug-all')
            if ((isinstance(self.verbose, str) and
                 self.verbose in ['basic', 'advanced', 'expert', 'guru'])
                or (isinstance(self.verbose, int) and (1<=self.verbose<=9))):
                cmd.append('--debug-level %s' % self.verbose)

        return cmd

    def _open_subprocess(self, args=None, passphrase=False):
        """Open a pipe to a GPG subprocess and return the file objects for
        communicating with it.

        :param list args: A list of strings of options and flags to pass to
                          ``GPG.binary``. This is input safe, meaning that
                          these values go through strict checks (see
                          ``parsers._sanitise_list``) before being passed to to
                          the input file descriptor for the GnuPG process.
                          Each string should be given exactly as it would be on
                          the commandline interface to GnuPG,
                          e.g. ["--cipher-algo AES256", "--default-key
                          A3ADB67A2CDB8B35"].

        :param bool passphrase: If True, the passphrase will be sent to the
                                stdin file descriptor for the attached GnuPG
                                process.
        """
        ## see http://docs.python.org/2/library/subprocess.html#converting-an\
        ##    -argument-sequence-to-a-string-on-windows
        cmd = ' '.join(self._make_args(args, passphrase))
        log.debug("Sending command to GnuPG process:%s%s" % (os.linesep, cmd))
        return subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={'LANGUAGE': 'en'})

    def _read_response(self, stream, result):
        """Reads all the stderr output from GPG, taking notice only of lines
        that begin with the magic [GNUPG:] prefix.

        Calls methods on the response object for each valid token found, with
        the arg being the remainder of the status line.

        :param stream: A byte-stream, file handle, or :class:`subprocess.PIPE`
                       to parse the for status codes from the GnuPG process.

        :param result: The result parser class from :mod:`_parsers` with which
                       to call ``handle_status`` and parse the output of
                       ``stream``.
        """
        lines = []
        while True:
            line = stream.readline()
            if len(line) == 0:
                break
            lines.append(line)
            line = line.rstrip()
            if line[0:9] == '[GNUPG:] ':
                # Chop off the prefix
                line = line[9:]
                log.status("%s" % line)
                L = line.split(None, 1)
                keyword = L[0]
                if len(L) > 1:
                    value = L[1]
                else:
                    value = ""
                result._handle_status(keyword, value)
            elif line[0:5] == 'gpg: ':
                log.warn("%s" % line)
            else:
                if self.verbose:
                    log.info("%s" % line)
                else:
                    log.debug("%s" % line)
        result.stderr = ''.join(lines)

    def _read_data(self, stream, result):
        """Read the contents of the file from GPG's stdout."""
        chunks = []
        while True:
            data = stream.read(1024)
            if len(data) == 0:
                break
            log.debug("read from stdout: %r" % data[:256])
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
        stderr = codecs.getreader(self._encoding)(process.stderr)
        rr = threading.Thread(target=self._read_response,
                              args=(stderr, result))
        rr.setDaemon(True)
        log.debug('stderr reader: %r', rr)
        rr.start()

        stdout = process.stdout
        dr = threading.Thread(target=self._read_data, args=(stdout, result))
        dr.setDaemon(True)
        log.debug('stdout reader: %r', dr)
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
            stdin = codecs.getwriter(self._encoding)(p.stdin)
        else:
            stdin = p.stdin
        if passphrase:
            _util._write_passphrase(stdin, passphrase, self._encoding)
        writer = _util._threaded_copy_data(file, stdin)
        self._collect_output(p, result, writer, stdin)
        return result

    def _recv_keys(self, keyids, keyserver=None):
        """Import keys from a keyserver.

        :param str keyids: A space-delimited string containing the keyids to
                           request.
        :param str keyserver: The keyserver to request the ``keyids`` from;
                              defaults to :property:`gnupg.GPG.keyserver`.
        """
        if not keyserver:
            keyserver = self.keyserver

        args = ['--keyserver {}'.format(keyserver),
                '--recv-keys {}'.format(keyids)]
        log.info('Requesting keys from %s: %s' % (keyserver, keyids))

        result = self._result_map['import'](self)
        proc = self._open_subprocess(args)
        self._collect_output(proc, result)
        log.debug('recv_keys result: %r', result.__dict__)
        return result

    def _sign_file(self, file, default_key=None, passphrase=None,
                   clearsign=True, detach=False, binary=False):
        """Create a signature for a file.

        :param file: The file stream (i.e. it's already been open()'d) to sign.
        :param str default_key: The key to sign with.
        :param str passphrase: The passphrase to pipe to stdin.
        :param bool clearsign: If True, create a cleartext signature.
        :param bool detach: If True, create a detached signature.
        :param bool binary: If True, do not ascii armour the output.
        """
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

        if default_key:
            args.append(str("--default-key %s" % default_key))

        ## We could use _handle_io here except for the fact that if the
        ## passphrase is bad, gpg bails and you can't write the message.
        result = self._result_map['sign'](self)
        proc = self._open_subprocess(args, passphrase is not None)
        try:
            if passphrase:
                _util._write_passphrase(proc.stdin, passphrase, self._encoding)
            writer = _util._threaded_copy_data(file, proc.stdin)
        except IOError as ioe:
            log.exception("Error writing message: %s" % ioe.message)
            writer = None
        self._collect_output(proc, result, writer, proc.stdin)
        return result

    def _encrypt(self, data, recipients,
                 default_key=None,
                 passphrase=None,
                 armor=True,
                 encrypt=True,
                 symmetric=False,
                 always_trust=True,
                 output=None,
                 cipher_algo='AES256',
                 digest_algo='SHA512',
                 compress_algo='ZLIB'):
        """Encrypt the message read from the file-like object ``data``.

        :param str data: The file or bytestream to encrypt.

        :param str recipients: The recipients to encrypt to. Recipients must
            be specified keyID/fingerprint. Care should be taken in Python2.x
            to make sure that the given fingerprint is in fact a string and
            not a unicode object.

        :param str default_key: The keyID/fingerprint of the key to use for
            signing. If given, ``data`` will be encrypted and signed.

        :param str passphrase: If given, and ``default_key`` is also given,
            use this passphrase to unlock the secret portion of the
            ``default_key`` to sign the encrypted ``data``. Otherwise, if
            ``default_key`` is not given, but ``symmetric=True``, then use
            this passphrase as the passphrase for symmetric
            encryption. Signing and symmetric encryption should *not* be
            combined when sending the ``data`` to other recipients, else the
            passphrase to the secret key would be shared with them.

        :param bool armor: If True, ascii armor the output; otherwise, the
            output will be in binary format. (Default: True)

        :param bool encrypt: If True, encrypt the ``data`` using the
            ``recipients`` public keys. (Default: True)

        :param bool symmetric: If True, encrypt the ``data`` to ``recipients``
            using a symmetric key. See the ``passphrase`` parameter. Symmetric
            encryption and public key encryption can be used simultaneously,
            and will result in a ciphertext which is decryptable with either
            the symmetric ``passphrase`` or one of the corresponding private
            keys.

        :param bool always_trust: If True, ignore trust warnings on recipient
            keys. If False, display trust warnings.  (default: True)

        :param str output: The output file to write to. If not specified, the
            encrypted output is returned, and thus should be stored as an
            object in Python. For example:

        >>> import shutil
        >>> import gnupg
        >>> if os.path.exists("doctests"):
        ...     shutil.rmtree("doctests")
        >>> gpg = gnupg.GPG(homedir="doctests")
        >>> key_settings = gpg.gen_key_input(key_type='RSA',
        ...                                  key_length=1024,
        ...                                  key_usage='ESCA',
        ...                                  passphrase='foo')
        >>> key = gpg.gen_key(key_settings)
        >>> message = "The crow flies at midnight."
        >>> encrypted = str(gpg.encrypt(message, key.printprint))
        >>> assert encrypted != message
        >>> assert not encrypted.isspace()
        >>> decrypted = str(gpg.decrypt(encrypted))
        >>> assert not decrypted.isspace()
        >>> decrypted
        'The crow flies at midnight.'

        :param str cipher_algo: The cipher algorithm to use. To see available
            algorithms with your version of GnuPG, do:
                ``$ gpg --with-colons --list-config ciphername``.
            The default ``cipher_algo``, if unspecified, is ``'AES256'``.

        :param str digest_algo: The hash digest to use. Again, to see which
            hashes your GnuPG is capable of using, do:
                ``$ gpg --with-colons --list-config digestname``.
            The default, if unspecified, is ``'SHA512'``.

        :param str compress_algo: The compression algorithm to use. Can be one
            of ``'ZLIB'``, ``'BZIP2'``, ``'ZIP'``, or ``'Uncompressed'``.
        """
        args = []

        if output:
            if getattr(output, 'fileno', None) is not None:
                ## avoid overwrite confirmation message
                if getattr(output, 'name', None) is None:
                    if os.path.exists(output):
                        os.remove(output)
                    args.append('--output %s' % output)
                else:
                    if os.path.exists(output.name):
                        os.remove(output.name)
                    args.append('--output %s' % output.name)

        if armor: args.append('--armor')
        if always_trust: args.append('--always-trust')
        if cipher_algo: args.append('--cipher-algo %s' % cipher_algo)
        if compress_algo: args.append('--compress-algo %s' % compress_algo)

        if default_key:
            args.append('--sign')
            args.append('--default-key %s' % default_key)
            if digest_algo:
                args.append('--digest-algo %s' % digest_algo)

        ## both can be used at the same time for an encrypted file which
        ## is decryptable with a passphrase or secretkey.
        if symmetric: args.append('--symmetric')
        if encrypt: args.append('--encrypt')

        if len(recipients) >= 1:
            log.debug("GPG.encrypt() called for recipients '%s' with type '%s'"
                      % (recipients, type(recipients)))

            if isinstance(recipients, (list, tuple)):
                for recp in recipients:
                    if not _util._py3k:
                        if isinstance(recp, unicode):
                            try:
                                assert _parsers._is_hex(str(recp))
                            except AssertionError:
                                log.info("Can't accept recipient string: %s"
                                         % recp)
                            else:
                                args.append('--recipient %s' % str(recp))
                                continue
                            ## will give unicode in 2.x as '\uXXXX\uXXXX'
                            args.append('--recipient %r' % recp)
                            continue
                    if isinstance(recp, str):
                        args.append('--recipient %s' % recp)

            elif (not _util._py3k) and isinstance(recp, basestring):
                for recp in recipients.split('\x20'):
                    args.append('--recipient %s' % recp)

            elif _util._py3k and isinstance(recp, str):
                for recp in recipients.split(' '):
                    args.append('--recipient %s' % recp)
                    ## ...and now that we've proven py3k is better...

            else:
                log.debug("Don't know what to do with recipients: '%s'"
                          % recipients)

        result = self._result_map['crypt'](self)
        log.debug("Got data '%s' with type '%s'."
                  % (data, type(data)))
        self._handle_io(args, data, result,
                        passphrase=passphrase, binary=True)
        log.debug('GPG.encrypt_file(): Result: %r', result.data)
        return result
