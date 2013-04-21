
__author__  = 'Isis Agora Lovecruft'
__contact__ = 'isis@leap.se'
__date__    = '1 April 2013'
__url__     = 'https://github.com/isislovecruft/python-gnupg'
__version__ = '0.4.0'
__license__ = 'AGPLv3'

from copyleft import disclaimer as copyright
from copyleft import txcopyright

import gnupg
from parsers import Crypt, DeleteResult, ListKeys
from parsers import GenKey, Sign, ImportResult, Verify
from gnupg import GPG

__all__ = ["gnupg", "copyright",
           "Crypt", "DeleteResult", "ListKeys",
           "GenKey", "Sign", "Encrypt", "ImportResult", "Verify"]
