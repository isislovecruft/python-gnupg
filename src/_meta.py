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


from psutil import process_iter

import atexit
import encodings
## For AOS, the locale module will need to point to a wrapper around the
## java.util.Locale class.
## See https://code.patternsinthevoid.net/?p=android-locale-hack.git
import locale
import os
import sys

import _util

from _parsers import _check_preferences
from _parsers import _fix_unsafe
from _parsers import _sanitise
from _util    import log
from _util    import _conf


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
        self.options = _sanitise(options) if options else None

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
        $PATH. If self.gpg.binary is in a directory being removed, it is
        symlinked to './gpg'

        :param str prog:
        """
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
            if gnupg_base == program_base:
                os.symlink(self.binary, os.path.join(os.getcwd(), 'gpg'))

            ## copy the original environment so that we can put it back later:
            env_copy = os.environ            ## this one should not be touched
            path_copy = os.environ.pop('PATH')
            log.debug("Created a copy of system PATH: %r" % path_copy)
            assert not os.environ.has_key('PATH'), "OS env kept $PATH anyway!"

            @staticmethod
            def remove_program_from_path(path, prog_base):
                """Remove all directories which contain a program from PATH.

                :param str path: The contents of the system environment's
                                 PATH.
                :param str prog_base: The base (directory only) portion of a
                                      program's location.
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

            @atexit.register
            def remove_symlinked_binary():
                loc = os.path.join(os.getcwd(), 'gpg')
                if os.path.islink(loc):
                    os.unline(loc)
                    log.debug("Removed binary symlink '%s'" % loc)

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
            log.info("Setting homedir to '%s'" % hd)
            self._homedir = hd

    homedir = _util.InheritableProperty(_homedir_getter, _homedir_setter)
