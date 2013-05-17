
import gnupg
from parsers import Crypt, DeleteResult, ListKeys
from parsers import GenKey, Sign, ImportResult, Verify
import copyleft

from gnupg import GPG

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions

gnupg.__version__ = __version__
gnupg.__author__  = 'Isis Agora Lovecruft'
gnupg.__contact__ = 'isis@leap.se'
gnupg.__url__     = 'https://github.com/isislovecruft/python-gnupg'
gnupg.__license__ = copyleft.disclaimer

__all__ = ["gnupg", "copyright",
           "Crypt", "DeleteResult", "ListKeys",
           "GenKey", "Sign", "Encrypt", "ImportResult", "Verify"]
del copyleft
