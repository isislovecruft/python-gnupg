gpg package
=============

gpg module
------------

This module contains public classes for working with GnuPG_. To get started,
do:

>>> import gpg as gnupg
>>> gpg = gnupg.GPG()


.. automodule:: gpg
    :members:
    :undoc-members:
    :private-members:
    :show-inheritance:

.. _meta:

meta module
-----------

Contains the meta and base classes which :class:`gpg.GPG` inherits
from. Mostly, you shouldn't ever need to touch anything in here, unless you're
doing some serious hacking.


.. automodule:: gpg._meta
    :members:
    :private-members:
    :special-members:
    :exclude-members: _agent_proc, __module__, __dict__, _decode_errors, init,
                      __weakref__, _result_map, __metaclass__
    :show-inheritance:

.. _parsers:

parsers module
--------------

These are classes for parsing both user inputs and status file descriptor
flags from GnuPG's output. The latter are used in order to determine what our
GnuPG process is doing and retrieve information about its operations, which
are stored in corresponding classes in
:attr:`~gpg._meta.GPGBase._result_map`. Some status flags aren't handled yet
-- information on *all* of the flags (well, at least the documented ones…) can
be found in the :file:`docs/DETAILS` file in GnuPG's source_, which has been
included here_ as well.


.. automodule:: gpg._parsers
    :members:
    :undoc-members:
    :private-members:
    :show-inheritance:


.. _util:

util module
-----------

You shouldn't really need to mess with this module either, it mostly deals
with low-level IO and file handling operations, de-/en- coding issues, and
setting up basic package facilities such as logging.

.. automodule:: gpg._util
    :members:
    :undoc-members:
    :private-members:
    :show-inheritance:


About this fork
---------------

This is a modified version of python-gnupg_, (forked from version 0.3.2) which
was created by Vinay Sajip, which itself is a modification of GPG.py written
by Steve Traugott, which in turn is a modification of the pycrypto GnuPG
interface written by A.M. Kuchling.

This version is patched to sanitize untrusted inputs, due to the necessity of
executing ``subprocess.Popen([...], shell=True)`` in order to communicate with
GnuPG. Several speed improvements were also made based on code profiling, and
the API has been cleaned up to support an easier, more Pythonic, interaction.


Previous Authors' Documentation
-------------------------------

Steve Traugott's documentation:
 |
 |    Portions of this module are derived from A.M. Kuchling's well-designed
 |    GPG.py, using Richard Jones' updated version 1.3, which can be found in
 |    the pycrypto CVS repository on Sourceforge:
 |
 |    http://pycrypto.cvs.sourceforge.net/viewvc/pycrypto/gpg/GPG.py
 |
 |    This module is *not* forward-compatible with amk's; some of the old
 |    interface has changed.  For instance, since I've added decrypt
 |    functionality, I elected to initialize with a 'gpghome' argument instead
 |    of 'keyring', so that gpg can find both the public and secret keyrings.
 |    I've also altered some of the returned objects in order for the caller to
 |    not have to know as much about the internals of the result classes.
 |
 |    While the rest of ISconf is released under the GPL, I am releasing this
 |    single file under the same terms that A.M. Kuchling used for pycrypto.
 |
 |    Steve Traugott, stevegt@terraluna.org
 |    Thu Jun 23 21:27:20 PDT 2005


Vinay Sajip's documentation:
 |
 |    This version of the module has been modified from Steve Traugott's version
 |    (see http://trac.t7a.org/isconf/browser/trunk/lib/python/isconf/GPG.py) by
 |    Vinay Sajip to make use of the subprocess module (Steve's version uses
 |    os.fork() and so does not work on Windows). Renamed to gnupg.py to avoid
 |    confusion with the previous versions.
 |
 |    A unittest harness (test_gnupg.py) has also been added.
 |
 |    Modifications Copyright (C) 2008-2012 Vinay Sajip. All rights reserved.


.. _GnuPG: http://gnupg.org
.. _python-gnupg: https://code.google.com/p/python-gnupg/
.. _source: http://http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=shortlog;h=refs/heads/master
.. _here: ./_static/DETAILS.html
