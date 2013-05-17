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
'''log.py
----------
Logging module for python-gnupg.
'''

from __future__ import print_function
from datetime   import datetime
from functools  import wraps

import logging
import sys
import os

import _ansistrm

try:
    from logging import NullHandler
except:
    class NullHandler(logging.Handler):
        def handle(self, record):
            pass

import gnupg._ansistrm

#log = logging.getLogger('gnupg')
#if not log.handlers:
#    log.addHandler(NullHandler())


@wraps(logging.Logger)
def create_logger(level=logging.NOTSET):
    """Create a logger for python-gnupg at a specific message level."""

    log = logging.getLogger('gnupg')

    if level > logging.NOTSET:
        logging.captureWarnings(True)
        logging.logThreads = True
        log.setLevel(level)

        colorizer = gnupg._ansistrm.ColorizingStreamHandler(stream=sys.stdout)
        colorizer.setLevel(level)
        log.addHandler(colorizer)

        log.debug("Starting the logger...")

    if not log.handlers:
        log.addHandler(NullHandler())

    return log
