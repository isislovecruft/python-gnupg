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

import setuptools
import os
import versioneer


versioneer.versionfile_source = 'gnupg/_version.py'
versioneer.versionfile_build  = 'gnupg/_version.py'
versioneer.tag_prefix = ''
versioneer.parentdir_prefix = 'gnupg-'

__author__ = "Isis Agora Lovecruft"
__contact__ = 'isis@patternsinthevoid.net'
__url__ = 'https://github.com/isislovecruft/python-gnupg'


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

    return requirements, links


requires, deplinks = get_requirements()
print('Found requirements:')
[print('\t%s' % name) for name in requires]

print('Found dependency links:')
[print('\t%s' % uri) for uri in deplinks]


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

    install_requires=requires,
    dependency_links=deplinks,
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
