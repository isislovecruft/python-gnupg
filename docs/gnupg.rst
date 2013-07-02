gnupg Module
============

.. automodule:: gnupg
    :members:
    :undoc-members:
    :show-inheritance:

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
