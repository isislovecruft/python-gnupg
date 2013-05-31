#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

from __future__ import absolute_import

from .         import gnupg
from .         import copyleft
from .         import _ansistrm
from .         import _logger
from .         import _meta
from .         import _parsers
from .         import _util
from .gnupg    import GPG
from ._version import get_versions

gnupg.__author__  = 'Isis Agora Lovecruft'
gnupg.__contact__ = 'isis@leap.se'
gnupg.__url__     = 'https://github.com/isislovecruft/python-gnupg'
gnupg.__license__ = copyleft.disclaimer
__version__  = get_versions()['version']

__all__ = ["GPG"]

del gnupg
del copyleft
del get_versions
del _version
