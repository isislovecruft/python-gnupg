#!/usr/bin/env python
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
#______________________________________________________________________________
#
# NOTE: setuptools is currently (as of 27 May 2013) being merged back into its
# parent project, distribute. By using the included distribute_setup.py
# script, we make sure that we have a recent version of setuptools/distribute,
# which is the *only* Python packaging framework compatible at this point with
# both Python>=2.4 and Python3.x.
#

from __future__ import absolute_import
from __future__ import print_function

## Upgrade setuptools to a version which supports Python 2 and 3
#os.system('python ./distribute_setup.py')
## Upgrade pip to a version with proper SSL support
#os.system('python ./get-pip.py')

import setuptools
import versioneer
versioneer.versionfile_source = 'gnupg/_version.py'
versioneer.versionfile_build  = 'gnupg/_version.py'
versioneer.tag_prefix = ''
versioneer.parentdir_prefix = 'gnupg-'

__author__ = "Isis Agora Lovecruft"
__contact__ = 'isis@patternsinthevoid.net'
__url__ = 'https://github.com/isislovecruft/python-gnupg'


setuptools.setup(
    name = "gnupg",
    description="A Python wrapper for GnuPG",
    long_description = """\
This module allows easy access to GnuPG's key management, encryption and \
signature functionality from Python programs, by interacting with GnuPG \
through file descriptors. Input arguments are strictly checked and sanitised, \
and therefore this module should be safe to use in networked applications \
requiring direct user input. It is intended for use with Python 2.6 or \
greater.

Documentation can be found on readthedocs_.

.. _readthedocs: https://python-gnupg.readthedocs.org/en/latest/
""",
    license="GPLv3+",

    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),

    author=__author__,
    author_email=__contact__,
    maintainer=__author__,
    maintainer_email=__contact__,
    url=__url__,

    package_dir={'gnupg': 'gnupg'},
    packages=['gnupg'],
    package_data={'': ['README', 'LICENSE', 'TODO', 'requirements.txt']},
    scripts=['versioneer.py'],
    test_suite='gnupg.test.test_gnupg',

    install_requires=['psutil>=0.5.1'],
    extras_require={'docs': ["Sphinx>=1.1", "repoze.sphinx"]},

    platforms="Linux, BSD, OSX, Windows",
    download_url="https://github.com/isislovecruft/python-gnupg/archive/master.zip",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.0",
        "Programming Language :: Python :: 3.1",
        "Programming Language :: Python :: 3.2",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Utilities",]
)
