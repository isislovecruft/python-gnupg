#!/usr/bin/env python
#-*- coding: utf-8 -*-

from distutils.core import setup

__module__ = 'gnupg'
__version__ = "0.4.0"
__author__ = "Isis Agora Lovecruft"
__contact__ = 'isis@leap.se'
__date__  = "1 April 2013"

setup(name = "python-gnupg",
      description="A wrapper for the Gnu Privacy Guard (GPG or GnuPG)",
      long_description = "This module allows easy access to GnuPG's key \
management, encryption and signature functionality from Python programs. \
It is intended for use with Python 2.6 or greater.",
      license="""Copyright © 2013 Isis Lovecruft, et.al. see LICENSE file.""",
      version=__version__,
      author=__author__,
      author_email=__contact__,
      maintainer=__author__,
      maintainer_email=__contact__,
      url="https://github.com/isislovecruft/python-gnupg",
      packages=['gnupg', 'gnupg.tests'],
      platforms="Linux, BSD, OSX, Windows",
      download_url="https://github.com/isislovecruft/python-gnupg/archive/develop.zip",
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
