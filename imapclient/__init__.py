# Copyright (c) 2014, Menno Smits
# Released subject to the New BSD License
# Please see http://en.wikipedia.org/wiki/BSD_licenses

# version_info provides the version number in programmer friendly way.
# The 4th part will be either alpha, beta or final.

from .imapclient import *  # noqa: F401,F403
from .response_parser import *  # noqa: F401,F403
from .tls import *  # noqa: F401,F403
from .version import author as __author__  # noqa: F401
from .version import version as __version__  # noqa: F401
from .version import version_info  # noqa: F401


def __getattr__(name):
    # Lazy import: AsyncIMAPClient (and its aioimaplib dependency) is only
    # loaded when explicitly requested, so ``import imapclient`` never
    # requires the vendored deps/ tree to be present.
    if name == "AsyncIMAPClient":
        from .aioimapclient import AsyncIMAPClient

        return AsyncIMAPClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
