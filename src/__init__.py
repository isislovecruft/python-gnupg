#-*- encoding: utf-8 -*-

from .copyleft import disclaimer as copyright
from .copyleft import txcopyright

import gnupg
from parsers import Crypt, DeleteResult, ListKeys
from parsers import GenKey, Sign, ImportResult, Verify
from gnupg import GPG

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions

gnupg.__version__ = __version__
gnupg.__author__  = 'Isis Agora Lovecruft'
gnupg.__contact__ = 'isis@leap.se'
gnupg.__url__     = 'https://github.com/isislovecruft/python-gnupg'
gnupg.__license__ = copyright

__all__ = ["gnupg", "copyright",
           "Crypt", "DeleteResult", "ListKeys",
           "GenKey", "Sign", "Encrypt", "ImportResult", "Verify"]
