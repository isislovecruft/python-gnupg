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

from __future__ import absolute_import
from __future__ import print_function

import platform
import setuptools
import sys
import os
import versioneer

try:
    import __pypy__
except ImportError:
    _isPyPy = False
else:
    _isPyPy = True


versioneer.versionfile_source = 'pretty_bad_protocol/_version.py'
versioneer.versionfile_build  = 'pretty_bad_protocol/_version.py'
versioneer.tag_prefix = ''
versioneer.parentdir_prefix = 'pretty-bad-protocol-'

__author__ = "Isis Agora Lovecruft"
__contact__ = 'isis@patternsinthevoid.net'
__url__ = 'https://github.com/isislovecruft/python-gnupg'


def python26():
    """Returns True if we're running on Python2.6."""
    if sys.version[:3] == "2.6":
        return True
    return False

def get_requirements():
    """Extract the list of requirements from our requirements.txt.

    :rtype: 2-tuple
    :returns: Two lists, the first is a list of requirements in the form of
        pkgname==version. The second is a list of URIs or VCS checkout strings
        which specify the dependency links for obtaining a copy of the
        requirement.
    """
    requirements_file = os.path.join(os.getcwd(), 'requirements.txt')
    requirements = []
    links=[]
    try:
        with open(requirements_file) as reqfile:
            for line in reqfile.readlines():
                line = line.strip()
                if line.startswith('#'):
                    continue
                elif line.startswith(
                        ('https://', 'git://', 'hg://', 'svn://')):
                    links.append(line)
                else:
                    requirements.append(line)

    except (IOError, OSError) as error:
        print(error)

    if python26():
        # Required to make `collections.OrderedDict` available on Python<=2.6
        requirements.append('ordereddict==1.1#a0ed854ee442051b249bfad0f638bbec')

    # Don't try to install psutil on PyPy:
    if _isPyPy:
        for line in requirements[:]:
            if line.startswith('psutil'):
                print("Not installing %s on PyPy..." % line)
                requirements.remove(line)

    return requirements, links


requires, deplinks = get_requirements()


setuptools.setup(
    name = "pretty-bad-protocol",
    description="A Python wrapper for GnuPG",
    long_description = """\
This module allows easy access to GnuPG's key management, encryption and \
signature functionality from Python programs, by interacting with GnuPG \
through file descriptors. Input arguments are strictly checked and sanitised, \
and therefore this module should be safe to use in networked applications \
requiring direct user input. It is intended for use on Windows, MacOS X, BSD, \
or Linux, with Python 2.6, Python 2.7, Python 3.3, Python 3.4, or PyPy.
""",
    license="GPLv3+",

    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),

    author=__author__,
    author_email=__contact__,
    maintainer=__author__,
    maintainer_email=__contact__,
    url=__url__,

    package_dir={
        'pretty_bad_protocol': 'pretty_bad_protocol',
    },
    packages=['pretty_bad_protocol'],
    package_data={'': ['README', 'LICENSE', 'TODO', 'requirements.txt']},
    scripts=['versioneer.py'],
    test_suite='pretty_bad_protocol.test.test_gnupg',

    install_requires=requires,
    dependency_links=deplinks,
    extras_require={'docs': ["Sphinx>=1.1",
                             "sphinxcontrib-fulltoc==1.0"]},

    platforms="Linux, BSD, OSX, Windows",
    download_url="https://github.com/isislovecruft/python-gnupg/archive/master.zip",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: Android",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: BSD",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Utilities",]
)
