
import gnupg
import copyleft

from gnupg import GPG

from ._version import get_versions
__version__ = get_versions()['version']

gnupg.__version__ = __version__
gnupg.__author__  = 'Isis Agora Lovecruft'
gnupg.__contact__ = 'isis@leap.se'
gnupg.__url__     = 'https://github.com/isislovecruft/python-gnupg'
gnupg.__license__ = copyleft.disclaimer

__all__ = ["GPG"]

del gnupg
del copyleft
del get_versions
