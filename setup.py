#!/usr/bin/env python
#-*- coding: utf-8 -*-
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

import inspect
import os

## Upgrade setuptools to a version which supports Python 2 and 3
#os.system('python ./distribute_setup.py')
## Upgrade pip to a version with proper SSL support
#os.system('python ./get-pip.py')

import setuptools
import versioneer
versioneer.versionfile_source = 'src/_version.py'
versioneer.versionfile_build  = 'gnupg/_version.py'
versioneer.tag_prefix = ''
versioneer.parentdir_prefix = 'python-gnupg-'

__author__ = "Isis Agora Lovecruft"
__contact__ = 'isis@leap.se'
__url__ = 'https://github.com/isislovecruft/python-gnupg \
https://python-gnupg.readthedocs.org'

def get_current_dir():
    """Current dir of this file, regardless of where we're called from."""
    here = inspect.getabsfile(inspect.currentframe()).rsplit(os.path.sep, 1)[0]
    return here

def get_deps_reqs():
    """Get dependencies from the pip requirements.txt file."""
    requirements_file = os.path.join(get_current_dir(), 'requirements.txt')
    dependency_links = []
    install_requires = []
    with open(requirements_file) as pipfile:
        for line in pipfile.readlines():
            line = line.strip()
            if not line.startswith('#'):
                if line.startswith('https'):
                    dependency_links.append(line)
                    continue
                else:
                    install_requires.append(line)
    return dependency_links, install_requires
deps, reqs = get_deps_reqs()
print('%s' % deps)
print('%s' % reqs)


def run_distribute_setup_script():
    """Run the setuptools/distribute setup script."""
    script = os.path.join(get_current_dir(), 'distribute_setup.py')
    os.system(script)

setuptools.setup(
    name = "python-gnupg",
    description="A Python wrapper for GnuPG",
    long_description = "This module allows easy access to GnuPG's key \
management, encryption and signature functionality from Python programs. \
It is intended for use with Python 2.6 or greater.",
    license="AGPLv3",

    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),

    author=__author__,
    author_email=__contact__,
    maintainer=__author__,
    maintainer_email=__contact__,
    url=__url__,

    package_dir={'gnupg': 'gnupg'},
    packages=['gnupg'],

    install_requires=reqs,
    dependency_links=deps,
    extras_require={'docs': ["Sphinx>=1.1"]},

    platforms="Linux, BSD, OSX, Windows",
    download_url="https://github.com/isislovecruft/python-gnupg/archive/master.zip",
    classifiers=[
        'Development Status :: 4 - Alpha',
        "Intended Audience :: Developers",
        'Classifier:: License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.0",
        "Programming Language :: Python :: 3.1",
        "Programming Language :: Python :: 3.2",
        "Topic :: Software Development :: Libraries :: Python Modules",
        'Classifier:: Topic :: Security :: Cryptography',
        'Classifier:: Topic :: Software Development :: Libraries :: Python Modules',
        'Classifier:: Topic :: Utilities',]
)
