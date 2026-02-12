# Copyright (c) 2014, Menno Smits
# Released subject to the New BSD License
# Please see http://en.wikipedia.org/wiki/BSD_licenses

from typing import Any, Dict, List
from unittest.mock import AsyncMock

from .aioimapclient import AsyncIMAPClient


class TestableAsyncIMAPClient(AsyncIMAPClient):
    """Wrapper of :py:class:`imapclient.aioimapclient.AsyncIMAPClient` that
    mocks all interaction with real IMAP server.

    This class should only be used in tests, where you can safely
    interact with the async imapclient without running commands on a
    real IMAP account.
    """

    def __init__(self) -> None:
        super().__init__("somehost")

    def _create_IMAP4(self) -> "MockAsyncIMAP4":
        return MockAsyncIMAP4()


class MockAsyncIMAP4(AsyncMock):
    """Mock aioimaplib IMAP4 transport for testing.

    Provides the same exception hierarchy as the real
    ``aioimaplib.IMAP4`` so that ``except self._imap.error`` and
    friends work correctly in the async client code.
    """

    class error(Exception):
        pass

    class abort(error):
        pass

    class readonly(abort):
        pass

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.use_uid = True
        self.sent = b""  # Accumulates what was given to send()
        self.tagged_commands: Dict[Any, Any] = {}
        self.untagged_responses: Dict[Any, Any] = {}
        self.capabilities: List[str] = []
        self._starttls_done = False
        self._tls_established = False
        self.state = "AUTH"
        self.timeout = None
        self.host = "somehost"
        self._writer = None

    async def send(self, data: bytes) -> None:
        self.sent += data

    async def connect(self) -> "MockAsyncIMAP4":
        return self

    def _new_tag(self) -> str:
        return "tag"

    def socket(self):
        return None

    def _untagged_response(self, typ, dat, name):
        if typ == "NO":
            return typ, dat
        if name not in self.untagged_responses:
            return typ, [None]
        data = self.untagged_responses.pop(name)
        return typ, data
