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

    :param str gpgbinary: The path to the GnuPG binary.
    :raises: :exc:RuntimeError if it appears that GnuPG is not installed.
    :rtype: str
    :returns: The absolute path to the GnuPG binary to use, if no exceptions
              occur.
    """
    binary = None
    if gpgbinary is not None:
        if not os.path.isabs(gpgbinary):
            try: binary = _which(gpgbinary)[0]
            except IndexError as ie: logger.debug(ie.message)
    if binary is None:
        try: binary = _which('gpg')[0]
        except IndexError: raise RuntimeError("gpg is not installed")
    try:
        assert os.path.isabs(binary), "Path to gpg binary not absolute"
        assert not os.path.islink(binary), "Path to gpg binary is symlink"
        assert os.access(binary, os.X_OK), "Lacking +x perms for gpg binary"
    except (AssertionError, AttributeError) as ae:
        logger.debug("util._find_gpgbinary(): %s" % ae.message)
    else:
        return binary

def _has_readwrite(path):
    """
    Determine if the real uid/gid of the executing user has read and write
    permissions for a directory or a file.

    :param str path: The path to the directory or file to check permissions
                     for.
    :rtype: bool
    :returns: True if real uid/gid has read+write permissions, False otherwise.
    """
    return os.access(path, os.R_OK and os.W_OK)

def _is_file(input):
    """Check that the size of the thing which is supposed to be a filename has
    size greater than zero, without following symbolic links or using
    :func:os.path.isfile.

    :param input: An object to check.
    :rtype: bool
    :returns: True if :param:input is file-like, False otherwise.
    """
    try:
        assert os.lstat(input).st_size > 0, "not a file: %s" % input
    except (AssertionError, TypeError) as error:
        logger.debug(error.message)
        return False
    else:
        return True

def _is_stream(input):
    """Check that the input is a byte stream.

    :param input: An object provided for reading from or writing to.
    :rtype: bool
    :returns: True if :param:input is a stream, False if otherwise.
    """
    return isinstance(input, BytesIO) or isinstance(input, StringIO)

def _is_list_or_tuple(instance):
    """Check that ``instance`` is a list or tuple.

    :param instance: The object to type check.
    :rtype: bool
    :returns: True if ``instance`` is a list or tuple, False otherwise.
    """
    return isinstance(instance,list) or isinstance(instance,tuple)

def _make_binary_stream(s, encoding):
    """
    xxx fill me in
    """
    try:
        if _py3k:
            if isinstance(s, str):
                s = s.encode(encoding)
        else:
            if type(s) is not str:
                s = s.encode(encoding)
        from io import BytesIO
        rv = BytesIO(s)
    except ImportError:
        rv = StringIO(s)
    return rv

## xxx unused function?
def _today():
    """Get the current date.

    :rtype: str
    :returns: The date, in the format '%Y-%m-%d'.
    """
    now_string = datetime.now().__str__()
    return now_string.split(' ', 1)[0]

def _which(executable, flags=os.X_OK):
    """Borrowed from Twisted's :mod:twisted.python.proutils .

    Search PATH for executable files with the given name.

    On newer versions of MS-Windows, the PATHEXT environment variable will be
    set to the list of file extensions for files considered executable. This
    will normally include things like ".EXE". This fuction will also find files
    with the given name ending with any of these extensions.

    On MS-Windows the only flag that has any meaning is os.F_OK. Any other
    flags will be ignored.

    Note: This function does not help us prevent an attacker who can already
    manipulate the environment's PATH settings from placing malicious code
    higher in the PATH. It also does happily follows links.

    :param str name: The name for which to search.
    :param int flags: Arguments to L{os.access}.
    :rtype: list
    :returns: A list of the full paths to files found, in the order in which
              they were found.
    """
    result = []
    exts = filter(None, os.environ.get('PATHEXT', '').split(os.pathsep))
    path = os.environ.get('PATH', None)
    if path is None:
        return []
    for p in os.environ.get('PATH', '').split(os.pathsep):
        p = os.path.join(p, executable)
        if os.access(p, flags):
            result.append(p)
        for e in exts:
            pext = p + e
            if os.access(pext, flags):
                result.append(pext)
    return result
