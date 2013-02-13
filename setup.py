from distutils.core import setup

from gnupg import __version__ as version

setup(name = "python-gnupg",
    description="A wrapper for the Gnu Privacy Guard (GPG or GnuPG)",
    long_description = "This module allows easy access to GnuPG's key \
management, encryption and signature functionality from Python programs. \
It is intended for use with Python 2.4 or greater.",
    license="""Copyright (C) 2008-2012 by Vinay Sajip. All Rights Reserved. See LICENSE for license.""",
    version=version,
    author="Vinay Sajip",
    author_email="vinay_sajip@red-dove.com",
    maintainer="Vinay Sajip",
    maintainer_email="vinay_sajip@red-dove.com",
    url="http://packages.python.org/python-gnupg/index.html",
    py_modules=["gnupg"],
    platforms="No particular restrictions",
    download_url="http://python-gnupg.googlecode.com/files/python-gnupg-%s.tar.gz" % version,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        "Intended Audience :: Developers",
        'License :: OSI Approved :: BSD License',
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.4",
        "Programming Language :: Python :: 2.5",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.0",
        "Programming Language :: Python :: 3.1",
        "Programming Language :: Python :: 3.2",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
