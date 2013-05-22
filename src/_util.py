# -*- coding: utf-8 -*-
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
util.py
----------
Extra utilities for python-gnupg.
'''

from datetime import datetime

import codecs
import encodings
import os
import time
import threading
import random
import string
import sys

import _logger

try:
    from io import StringIO
    from io import BytesIO
except ImportError:
    from cStringIO import StringIO

try:
    unicode
    _py3k = False
    try:
        isinstance(__name__, basestring)
    except NameError:
        msg  = "Sorry, python-gnupg requires a Python version with proper"
        msg += " unicode support. Please upgrade to Python>=2.3."
        raise SystemExit(msg)
except NameError:
    _py3k = True


## Directory shortcuts:
_here = os.getcwd()
_test = os.path.join(os.path.join(_here, 'tests'), 'tmp') ## ./tests/tmp
_user = os.environ.get('HOME')                            ## $HOME
_ugpg = os.path.join(_user, '.gnupg')                     ## $HOME/.gnupg
_conf = os.path.join(os.path.join(_user, '.config'), 'python-gnupg')
                                     ## $HOME/.config/python-gnupg

## Logger is disabled by default
log = _logger.create_logger(0)


def find_encodings(enc=None, system=False):
    """Find functions for encoding translations for a specific codec.

    :param str enc: The codec to find translation functions for. It will be
                    normalized by converting to lowercase, excluding
                    everything which is not ascii, and hyphens will be
                    converted to underscores.

    :param bool system: If True, find encodings based on the system's stdin
                        encoding, otherwise assume utf-8.

    :raises: :exc:LookupError if the normalized codec, ``enc``, cannot be
             found in Python's encoding translation map.
    """
    if not enc:
        enc = 'utf-8'

    if system:
        if getattr(sys.stdin, 'encoding', None) is None:
            enc = sys.stdin.encoding
            log.debug("Obtained encoding from stdin: %s" % enc)
        else:
            enc = 'ascii'

    ## have to have lowercase to work, see
    ## http://docs.python.org/dev/library/codecs.html#standard-encodings
    enc = enc.lower()
    codec_alias = encodings.normalize_encoding(enc)

    codecs.register(encodings.search_function)
    coder = codecs.lookup(codec_alias)

    return coder

def _copy_data(instream, outstream):
    """Copy data from one stream to another.

    :type instream: :class:`io.BytesIO` or :class:`io.StringIO` or file
    :param instream: A byte stream or open file to read from.
    :param file outstream: The file descriptor of a tmpfile to write to.
    """
    sent = 0

    #try:
    #    #assert (util._is_stream(instream)
    #    #        or isinstance(instream, file)), "instream not stream or file"
    #    assert isinstance(outstream, file), "outstream is not a file"
    #except AssertionError as ae:
    #    log.exception(ae)
    #    return

    coder = find_encodings()

    while True:
        data = instream.read(1024)
        if len(data) == 0:
            break
        sent += len(data)
        log.debug("Sending chunk %d bytes:\n%s"
                  % (sent, data))
        try:
            outstream.write(data)
        except UnicodeError:
            try:
                outstream.write(coder.encode(data))
            except IOError:
                log.exception("Error sending data: Broken pipe")
                break
        except IOError:
            # Can get 'broken pipe' errors even when all data was sent
            log.exception('Error sending data: Broken pipe')
            break
    try:
        outstream.close()
    except IOError as ioe:
        log.error("Unable to close outstream %s:\r\t%s" % (outstream, ioe))
    else:
        log.debug("Closed outstream: %d bytes sent." % sent)

def _create_if_necessary(directory):
    """Create the specified directory, if necessary.

    :param str directory: The directory to use.
    :rtype: bool
    :returns: True if no errors occurred and the directory was created or
              existed beforehand, False otherwise.
    """

    if not os.path.isabs(directory):
        log.debug("Got non-absolute path: %s" % directory)
        directory = os.path.abspath(directory)

    if not os.path.isdir(directory):
        log.info("Creating directory: %s" % directory)
        try:
            os.makedirs(directory, 0x1C0)
        except OSError as ose:
            log.error(ose, exc_info=1)
            return False
        else:
            log.debug("Created directory.")
    return True

def _find_binary(binary=None):
    """Find the absolute path to the GnuPG binary.

    Also run checks that the binary is not a symlink, and check that
    our process real uid has exec permissions.

    :param str binary: The path to the GnuPG binary.
    :raises: :exc:RuntimeError if it appears that GnuPG is not installed.
    :rtype: str
    :returns: The absolute path to the GnuPG binary to use, if no exceptions
              occur.
    """
    gpg_binary = None
    if binary is not None:
        if not os.path.isabs(binary):
            try: binary = _which(binary)[0]
            except IndexError as ie:
                log.error(ie.message)
    if binary is None:
        try: binary = _which('gpg')[0]
        except IndexError: raise RuntimeError("GnuPG is not installed!")
    try:
        assert os.path.isabs(binary), "Path to gpg binary not absolute"
        assert not os.path.islink(binary), "Path to gpg binary is symlink"
        assert os.access(binary, os.X_OK), "Lacking +x perms for gpg binary"
    except (AssertionError, AttributeError) as ae:
        log.error(ae.message)
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
    return os.access(path, os.R_OK ^ os.W_OK)

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
    except (AssertionError, TypeError, IOError, OSError) as err:
        log.error(err.message, exc_info=1)
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

def _make_passphrase(length=None, save=False, file=None):
    """Create a passphrase and write it to a file that only the user can read.

    This is not very secure, and should not be relied upon for actual key
    passphrases.

    :param int length: The length in bytes of the string to generate.

    :param file file: The file to save the generated passphrase in. If not
        given, defaults to 'passphrase-<the real user id>-<seconds since
        epoch>' in the top-level directory.
    """
    if not length:
        length = 40

    passphrase = _make_random_string(length)

    if save:
        ruid, euid, suid = os.getresuid()
        gid = os.getgid()
        now = time.mktime(time.gmtime())

        if not file:
            filename = str('passphrase-%s-%s' % uid, now)
            file = os.path.join(_repo, filename)

        with open(file, 'a') as fh:
            fh.write(passphrase)
            fh.flush()
            fh.close()
            os.chmod(file, 0600)
            os.chown(file, ruid, gid)

        log.warn("Generated passphrase saved to %s" % file)
    return passphrase

def _make_random_string(length):
    """Returns a random lowercase, uppercase, alphanumerical string.

    :param int length: The length in bytes of the string to generate.
    """
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for x in range(length))

def _next_year():
    """Get the date of today plus one year.

    :rtype: str
    :returns: The date of this day next year, in the format '%Y-%m-%d'.
    """
    now = datetime.now().__str__()
    date = now.split(' ', 1)[0]
    year, month, day = date.split('-', 2)
    next_year = str(int(year)+1)
    return '-'.join((next_year, month, day))

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
    log.debug('%r, %r, %r', copy_thread, instream, outstream)
    copy_thread.start()
    return copy_thread

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

def _write_passphrase(stream, passphrase, encoding):
    """Write the passphrase from memory to the GnuPG process' stdin.

    :type stream: file, :class:BytesIO, or :class:StringIO
    :param stream: The input file descriptor to write the password to.
    :param str passphrase: The passphrase for the secret key material.
    :param str encoding: The data encoding expected by GnuPG. Usually, this
                         is ``sys.getfilesystemencoding()``.
    """
    passphrase = '%s\n' % passphrase
    passphrase = passphrase.encode(encoding)
    stream.write(passphrase)
    log.debug("Wrote passphrase on stdin.")


class InheritableProperty(object):
  """Based on the emulation of PyProperty_Type() in Objects/descrobject.c"""

  def __init__(self, fget=None, fset=None, fdel=None, doc=None):
    self.fget = fget
    self.fset = fset
    self.fdel = fdel
    self.__doc__ = doc

  def __get__(self, obj, objtype=None):
    if obj is None:
      return self
    if self.fget is None:
      raise AttributeError, "unreadable attribute"
    if self.fget.__name__ == '<lambda>' or not self.fget.__name__:
      return self.fget(obj)
    else:
      return getattr(obj, self.fget.__name__)()

  def __set__(self, obj, value):
    if self.fset is None:
      raise AttributeError, "can't set attribute"
    if self.fset.__name__ == '<lambda>' or not self.fset.__name__:
      self.fset(obj, value)
    else:
      getattr(obj, self.fset.__name__)(value)

  def __delete__(self, obj):
    if self.fdel is None:
      raise AttributeError, "can't delete attribute"
    if self.fdel.__name__ == '<lambda>' or not self.fdel.__name__:
      self.fdel(obj)
    else:
      getattr(obj, self.fdel.__name__)()
