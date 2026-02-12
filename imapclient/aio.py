# Copyright (c) 2015, Menno Smits
# Released subject to the New BSD License
# Please see http://en.wikipedia.org/wiki/BSD_licenses

"""Async IMAP client package entry point.

Usage::

    from imapclient.aio import AsyncIMAPClient

    async with AsyncIMAPClient("imap.example.com") as client:
        await client.login("user", "pass")
        await client.select_folder("INBOX")
        messages = await client.search("ALL")
"""

from .aioimapclient import *  # noqa: F401,F403
from .response_parser import *  # noqa: F401,F403
from .version import author as __author__  # noqa: F401
from .version import version as __version__  # noqa: F401
from .version import version_info  # noqa: F401
