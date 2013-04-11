from distutils.core import setup

from gnupg.gnupg import __version__ as version
from gnupg.gnupg import __author__ as author

setup(name = "python-gnupg",
      description="A wrapper for the Gnu Privacy Guard (GPG or GnuPG)",
      long_description = "This module allows easy access to GnuPG's key \
management, encryption and signature functionality from Python programs. \
It is intended for use with Python 2.6 or greater.",
      license="""Copyright © 2013 Isis Lovecruft, et.al. see LICENSE file.""",
      version=version,
      author=author,
      author_email="isis@leap.se",
      maintainer="Isis Agora Lovecruft",
      maintainer_email="isis@leap.se",
      url="https://github.com/isislovecruft/python-gnupg",
      packages_dir={'': 'gnupg'},
      packages=[''],
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
