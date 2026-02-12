# Copyright (c) 2015, Menno Smits
# Released subject to the New BSD License
# Please see http://en.wikipedia.org/wiki/BSD_licenses

"""Live integration tests for :class:`AsyncIMAPClient` against Fastmail.

These tests connect to a real IMAP server using credentials from
environment variables (loaded from ``deps/aioimaplib/.env`` by the
conftest).  If the credentials are not set the entire module is skipped.

Run with::

    python -m pytest tests/test_aioimapclient_live.py -v
"""

from __future__ import annotations

import asyncio
import os
import ssl
from datetime import datetime
from email.utils import make_msgid

import pytest

from imapclient.aioimapclient import AsyncIMAPClient
from imapclient.exceptions import CapabilityError, IMAPClientError
from imapclient.imapclient import DELETED, RECENT, SocketTimeout
from imapclient.util import to_bytes, to_unicode

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

_USER = os.getenv("AIOIMAPLIB_FASTMAIL_USER")
_PASSWORD = os.getenv("AIOIMAPLIB_FASTMAIL_PASSWORD")
_HOST = os.getenv("AIOIMAPLIB_FASTMAIL_IMAP_HOST", "imap.fastmail.com")
_PORT = int(os.getenv("AIOIMAPLIB_FASTMAIL_IMAP_PORT", "993"))

pytestmark = pytest.mark.skipif(
    not _USER or not _PASSWORD,
    reason="Live Fastmail credentials not set in environment",
)

# ---------------------------------------------------------------------------
# Test messages
# ---------------------------------------------------------------------------

SIMPLE_MESSAGE = "Subject: something\r\n\r\nFoo\r\n"

MULTIPART_MESSAGE = """\
From: Bob Smith <bob@smith.com>
To: Some One <some@one.com>, foo@foo.com
Date: Tue, 16 Mar 2010 16:45:32 +0000
MIME-Version: 1.0
Subject: A multipart message
Content-Type: multipart/mixed; boundary="===============1534046211=="

--===============1534046211==
Content-Type: text/html; charset="us-ascii"
Content-Transfer-Encoding: quoted-printable

<html><body>
Here is the first part.
</body></html>

--===============1534046211==
Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: 7bit

Here is the second part.

--===============1534046211==--
""".replace("\n", "\r\n")

SMILE = "\u263a"
SMILE_MESSAGE = b"""\
Subject: stuff
Content-Type: text/plain; charset="UTF-8"

\xe2\x98\xba
""".replace(b"\n", b"\r\n")

BASE_FOLDER = "__async_imapclient_test"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_client(timeout=30):
    """Create a connected, logged-in ``AsyncIMAPClient``."""
    client = AsyncIMAPClient(_HOST, _PORT, ssl=True, timeout=timeout)
    await client._imap.connect()
    client._apply_read_timeout()
    await client.login(_USER, _PASSWORD)
    return client


async def _quiet_logout(client):
    """Logout ignoring errors."""
    try:
        await client.logout()
    except Exception:
        try:
            await client.shutdown()
        except Exception:
            pass


async def _ensure_folder(client, folder):
    """Create *folder* if it does not exist."""
    if not await client.folder_exists(folder):
        await client.create_folder(folder)


async def _clear_folder(client, folder):
    """Select *folder*, delete all messages and expunge."""
    await client.select_folder(folder)
    msgs = await client.search("ALL")
    if msgs:
        await client.delete_messages(msgs)
        await client.expunge()


async def _cleanup_test_folders(client):
    """Remove all ``BASE_FOLDER*`` folders."""
    try:
        await client.close_folder()
    except Exception:
        pass
    folders = await client.list_folders("", BASE_FOLDER + "*")
    # Sort deepest-first so children are deleted before parents
    folder_names = sorted(
        [f[2] for f in folders],
        key=lambda n: n.count("."),
        reverse=True,
    )
    for name in folder_names:
        try:
            await client.delete_folder(name)
        except IMAPClientError:
            pass


# ---------------------------------------------------------------------------
# Function-scoped fixtures (each test gets its own client & event loop)
# ---------------------------------------------------------------------------


@pytest.fixture
async def client():
    """A connected, logged-in client for a single test."""
    c = await _make_client()
    yield c
    await _quiet_logout(c)


@pytest.fixture
async def test_folder(client):
    """Create BASE_FOLDER, select it, yield the name, then clean up."""
    await _cleanup_test_folders(client)
    await _ensure_folder(client, BASE_FOLDER)
    await client.select_folder(BASE_FOLDER)
    yield BASE_FOLDER
    await _cleanup_test_folders(client)


# ---------------------------------------------------------------------------
# Group 1: Connection & Authentication
# ---------------------------------------------------------------------------


async def test_context_manager():
    """async with AsyncIMAPClient(...) connects and logs out."""
    async with AsyncIMAPClient(_HOST, _PORT, ssl=True, timeout=30) as c:
        await c.login(_USER, _PASSWORD)
        caps = await c.capabilities()
        assert len(caps) > 0


async def test_login_and_logout():
    """Explicit login + logout round-trip."""
    client = AsyncIMAPClient(_HOST, _PORT, ssl=True, timeout=30)
    await client._imap.connect()
    client._apply_read_timeout()
    resp = await client.login(_USER, _PASSWORD)
    assert resp is not None
    resp = await client.logout()
    assert resp is not None


async def test_shutdown():
    """shutdown() closes the connection without a LOGOUT handshake."""
    client = await _make_client()
    await client.shutdown()


async def test_welcome(client):
    """The welcome property should be available after connect."""
    w = client.welcome
    assert w is not None
    assert len(w) > 0


async def test_socket(client):
    """socket() should return something (transport info)."""
    # aioimaplib may return None for socket(); just verify no crash
    client.socket()


# ---------------------------------------------------------------------------
# Group 2: Capabilities
# ---------------------------------------------------------------------------


async def test_capabilities(client):
    caps = await client.capabilities()
    assert isinstance(caps, tuple)
    assert len(caps) > 1
    for cap in caps:
        assert isinstance(cap, bytes)


async def test_has_capability(client):
    assert await client.has_capability("IMAP4rev1")
    assert not await client.has_capability("THIS_WILL_NEVER_EXIST")


# ---------------------------------------------------------------------------
# Group 3: Namespace
# ---------------------------------------------------------------------------


async def test_namespace(client):
    if not await client.has_capability("NAMESPACE"):
        pytest.skip("Server does not support NAMESPACE")
    ns = await client.namespace()
    assert len(ns) == 3
    assert ns.personal is None or isinstance(ns.personal, tuple)
    assert ns.other is None or isinstance(ns.other, tuple)
    assert ns.shared is None or isinstance(ns.shared, tuple)


# ---------------------------------------------------------------------------
# Group 4: Folder Operations
# ---------------------------------------------------------------------------


async def test_list_folders(client):
    folders = await client.list_folders()
    names = [f[2] for f in folders]
    assert "INBOX" in names


async def test_list_sub_folders(client, test_folder):
    sub_name = BASE_FOLDER + ".subfolder_sub"
    await client.create_folder(sub_name)
    await client.subscribe_folder(sub_name)
    try:
        subs = await client.list_sub_folders("", BASE_FOLDER + "*")
        sub_names = [f[2] for f in subs]
        assert sub_name in sub_names
    finally:
        await client.unsubscribe_folder(sub_name)


async def test_create_and_delete_folder(client):
    folder = BASE_FOLDER + ".create_delete_test"
    try:
        await client.delete_folder(folder)
    except IMAPClientError:
        pass
    resp = await client.create_folder(folder)
    assert resp is not None
    assert await client.folder_exists(folder)
    await client.delete_folder(folder)
    assert not await client.folder_exists(folder)


async def test_rename_folder(client):
    old = BASE_FOLDER + ".rename_old"
    new = BASE_FOLDER + ".rename_new"
    for f in (old, new):
        try:
            await client.delete_folder(f)
        except IMAPClientError:
            pass
    await client.create_folder(old)
    resp = await client.rename_folder(old, new)
    assert isinstance(resp, bytes)
    assert not await client.folder_exists(old)
    assert await client.folder_exists(new)
    await client.delete_folder(new)


async def test_folder_exists(client):
    assert await client.folder_exists("INBOX")
    assert not await client.folder_exists("this_folder_will_never_exist_12345")


async def test_subscribe_unsubscribe(client, test_folder):
    sub_folder = BASE_FOLDER + ".sub_test"
    await _ensure_folder(client, sub_folder)
    await client.subscribe_folder(sub_folder)
    subs = await client.list_sub_folders("", BASE_FOLDER + "*")
    sub_names = [f[2] for f in subs]
    assert sub_folder in sub_names

    await client.unsubscribe_folder(sub_folder)
    subs = await client.list_sub_folders("", BASE_FOLDER + "*")
    sub_names = [f[2] for f in subs]
    assert sub_folder not in sub_names


async def test_select_and_close_folder(client, test_folder):
    resp = await client.select_folder(test_folder)
    assert b"EXISTS" in resp
    assert isinstance(resp[b"FLAGS"], tuple)
    await client.close_folder()


async def test_select_folder_readonly(client, test_folder):
    await client.append(test_folder, SIMPLE_MESSAGE)
    resp = await client.select_folder(test_folder, readonly=True)
    assert b"EXISTS" in resp
    assert resp[b"EXISTS"] >= 1


async def test_unselect_folder(client, test_folder):
    if not await client.has_capability("UNSELECT"):
        pytest.skip("Server does not support UNSELECT")
    await client.select_folder(test_folder)
    await client.unselect_folder()


async def test_folder_status(client, test_folder):
    status = await client.folder_status(test_folder)
    assert b"MESSAGES" in status
    assert b"RECENT" in status
    assert b"UNSEEN" in status
    assert b"UIDNEXT" in status
    assert b"UIDVALIDITY" in status


async def test_find_special_folder(client):
    # Fastmail should have a Sent or Trash folder
    from imapclient.aioimapclient import SENT, TRASH

    sent = await client.find_special_folder(SENT)
    trash = await client.find_special_folder(TRASH)
    # At least one should exist
    assert sent is not None or trash is not None


# ---------------------------------------------------------------------------
# Group 5: Message Operations
# ---------------------------------------------------------------------------


async def test_append_and_fetch(client, test_folder):
    msg_time = datetime.now().replace(microsecond=0)
    resp = await client.append(test_folder, SIMPLE_MESSAGE, ("abc", "def"), msg_time)
    assert isinstance(resp, bytes)

    await client.select_folder(test_folder)
    msgs = await client.search("ALL")
    assert len(msgs) >= 1

    msg_id = msgs[0]
    fetched = await client.fetch(msg_id, ["RFC822", "FLAGS", "INTERNALDATE"])
    assert msg_id in fetched
    info = fetched[msg_id]
    assert b"RFC822" in info
    assert b"FLAGS" in info
    assert b"INTERNALDATE" in info
    assert b"something" in info[b"RFC822"]
    assert isinstance(info[b"INTERNALDATE"], datetime)


async def test_search_criteria(client, test_folder):
    await _clear_folder(client, test_folder)
    for subj in ("aaa", "bbb", "ccc"):
        await client.append(test_folder, "Subject: %s\r\n\r\nBody\r\n" % subj)

    await client.select_folder(test_folder)
    all_msgs = await client.search("ALL")
    assert len(all_msgs) == 3

    subj_msgs = await client.search(["SUBJECT", "aaa"])
    assert len(subj_msgs) == 1

    # Default (no criteria) should equal ALL
    default_msgs = await client.search()
    assert len(default_msgs) == len(all_msgs)


async def test_search_with_charset(client, test_folder):
    """Verify that charset= parameter is accepted and search doesn't crash.

    Note: Fastmail may not return body-search results for non-ASCII
    content, so we only assert the command succeeds without error and
    fall back to a known-good SUBJECT search as a correctness check.
    """
    await _clear_folder(client, test_folder)
    await client.append(test_folder, SMILE_MESSAGE)
    await client.select_folder(test_folder)

    # The server should accept the charset-encoded search without error
    msgs = await client.search(["BODY", SMILE], charset="UTF-8")
    assert isinstance(msgs, list)

    # SUBJECT search must work reliably
    msgs = await client.search(["SUBJECT", "stuff"], charset="UTF-8")
    assert len(msgs) == 1


async def test_fetch_envelope(client, test_folder):
    await _clear_folder(client, test_folder)
    msg_id_header = make_msgid()
    msg = ("Message-ID: %s\r\n" % msg_id_header) + MULTIPART_MESSAGE
    await client.append(test_folder, msg)
    await client.select_folder(test_folder)

    msgs = await client.search("ALL")
    assert len(msgs) >= 1
    fetched = await client.fetch(msgs[0], ["ENVELOPE"])
    info = fetched[msgs[0]]
    assert b"ENVELOPE" in info
    envelope = info[b"ENVELOPE"]
    assert envelope.subject == b"A multipart message"


async def test_fetch_bodystructure(client, test_folder):
    await _clear_folder(client, test_folder)
    await client.append(test_folder, MULTIPART_MESSAGE)
    await client.select_folder(test_folder)

    msgs = await client.search("ALL")
    fetched = await client.fetch(msgs[0], ["BODYSTRUCTURE"])
    info = fetched[msgs[0]]
    assert b"BODYSTRUCTURE" in info
    bs = info[b"BODYSTRUCTURE"]
    assert bs.is_multipart


async def test_copy(client, test_folder):
    await _clear_folder(client, test_folder)
    await client.append(test_folder, SIMPLE_MESSAGE)
    await client.select_folder(test_folder)
    msg_id = (await client.search("ALL"))[0]

    target = BASE_FOLDER + ".copy_target"
    await _ensure_folder(client, target)
    await client.copy(msg_id, target)

    await client.select_folder(target)
    target_msgs = await client.search("ALL")
    assert len(target_msgs) >= 1


async def test_move(client, test_folder):
    if not await client.has_capability("MOVE"):
        pytest.skip("Server does not support MOVE")

    await _clear_folder(client, test_folder)
    await client.append(test_folder, SIMPLE_MESSAGE)
    await client.select_folder(test_folder)
    msg_id = (await client.search("ALL"))[0]

    target = BASE_FOLDER + ".move_target"
    await _ensure_folder(client, target)
    await client.move(msg_id, target)

    # Source should have one fewer message
    remaining = await client.search("ALL")
    assert msg_id not in remaining

    # Target should have the message
    await client.select_folder(target)
    target_msgs = await client.search("ALL")
    assert len(target_msgs) >= 1


async def test_delete_messages(client, test_folder):
    await _clear_folder(client, test_folder)
    await client.append(test_folder, SIMPLE_MESSAGE)
    await client.select_folder(test_folder)
    msg_id = (await client.search("ALL"))[0]

    result = await client.delete_messages(msg_id)
    assert msg_id in result
    assert DELETED in result[msg_id]


async def test_expunge(client, test_folder):
    await _clear_folder(client, test_folder)
    await client.append(test_folder, SIMPLE_MESSAGE, flags=[DELETED])
    await client.select_folder(test_folder)

    text, resps = await client.expunge()
    assert isinstance(text, bytes)
    assert len(text) > 0
    assert isinstance(resps, list)


# ---------------------------------------------------------------------------
# Group 6: Flag Operations
# ---------------------------------------------------------------------------


async def test_flags(client, test_folder):
    await _clear_folder(client, test_folder)
    await client.append(test_folder, SIMPLE_MESSAGE)
    await client.select_folder(test_folder)
    msg_id = (await client.search("ALL"))[0]

    # set_flags
    result = await client.set_flags(msg_id, [b"abc", b"def"])
    assert msg_id in result
    flags = set(result[msg_id])
    flags.discard(RECENT)
    assert b"abc" in flags
    assert b"def" in flags

    # get_flags
    result = await client.get_flags(msg_id)
    assert msg_id in result
    flags = set(result[msg_id])
    flags.discard(RECENT)
    assert b"abc" in flags

    # add_flags
    result = await client.add_flags(msg_id, [b"ghi"])
    flags = set(result[msg_id])
    flags.discard(RECENT)
    assert b"ghi" in flags
    assert b"abc" in flags

    # remove_flags
    result = await client.remove_flags(msg_id, [b"ghi"])
    flags = set(result[msg_id])
    flags.discard(RECENT)
    assert b"ghi" not in flags
    assert b"abc" in flags

    # silent mode
    result = await client.set_flags(msg_id, [b"zzz"], silent=True)
    assert result is None


# ---------------------------------------------------------------------------
# Group 7: IDLE
# ---------------------------------------------------------------------------


async def test_idle(client, test_folder):
    if not await client.has_capability("IDLE"):
        pytest.skip("Server does not support IDLE")

    await _clear_folder(client, test_folder)
    await client.select_folder(test_folder)
    await client.idle()

    try:
        # Open a second connection and append a message
        client2 = await _make_client()
        try:
            await client2.select_folder(test_folder)
            await client2.append(test_folder, SIMPLE_MESSAGE)
        finally:
            await _quiet_logout(client2)

        # Wait for IDLE notification (up to 30 seconds)
        responses = []
        for _ in range(6):
            responses = await client.idle_check(timeout=5)
            if any(r == (1, b"EXISTS") for r in responses):
                break
    finally:
        text, more = await client.idle_done()

    assert isinstance(text, bytes)
    assert len(text) > 0
    assert isinstance(more, list)


# ---------------------------------------------------------------------------
# Group 8: NOOP
# ---------------------------------------------------------------------------


async def test_noop(client, test_folder):
    await client.select_folder(test_folder)
    text, resps = await client.noop()
    assert isinstance(text, bytes)
    assert len(text) > 0
    assert isinstance(resps, list)


# ---------------------------------------------------------------------------
# Group 9: Capability-Gated Methods
# ---------------------------------------------------------------------------


async def test_id(client):
    if not await client.has_capability("ID"):
        pytest.skip("Server does not support ID")
    result = await client.id_()
    # result can be a parsed dict-like structure or None
    # Just ensure no crash and we get something back
    assert result is not None


async def test_id_with_params(client):
    if not await client.has_capability("ID"):
        pytest.skip("Server does not support ID")
    result = await client.id_({"name": "aioimapclient-test", "version": "0.1"})
    assert result is not None


async def test_sort(client, test_folder):
    if not await client.has_capability("SORT"):
        pytest.skip("Server does not support SORT")

    await _clear_folder(client, test_folder)
    msg_tmpl = "Subject: Test\r\n\r\nBody"
    line = "\n" + ("x" * 72)
    for line_cnt in (10, 20, 30):
        await client.append(test_folder, msg_tmpl + (line * line_cnt))

    await client.select_folder(test_folder)
    messages = await client.sort("REVERSE SIZE")
    assert len(messages) == 3
    # Largest message should come first
    assert messages[0] > messages[-1]


async def test_thread(client, test_folder):
    if not await client.has_capability("THREAD=REFERENCES"):
        pytest.skip("Server does not support THREAD=REFERENCES")

    await _clear_folder(client, test_folder)
    for subj in ("a", "b", "c"):
        await client.append(test_folder, "Subject: %s\r\n\r\nBody\r\n" % subj)

    await client.select_folder(test_folder)
    threads = await client.thread()
    assert len(threads) == 3
    assert isinstance(threads[0], tuple)


async def test_enable(client, test_folder):
    if not await client.has_capability("ENABLE"):
        pytest.skip("Server does not support ENABLE")
    # ENABLE can only be issued in AUTH state (before SELECT).
    # We need a fresh connection for this.
    c = await _make_client()
    try:
        if await c.has_capability("CONDSTORE"):
            result = await c.enable("CONDSTORE")
            assert isinstance(result, list)
        else:
            pytest.skip("No CONDSTORE to enable")
    finally:
        await _quiet_logout(c)


async def test_acl(client, test_folder):
    if not await client.has_capability("ACL"):
        pytest.skip("Server does not support ACL")

    acls = await client.getacl(test_folder)
    assert isinstance(acls, list)
    # Should have at least one ACL entry (the owner)
    assert len(acls) >= 1
    who, rights = acls[0]
    assert len(who) > 0


async def test_quota(client):
    if not await client.has_capability("QUOTA"):
        pytest.skip("Server does not support QUOTA")

    root, quotas = await client.get_quota_root("INBOX")
    assert root is not None
    # quotas may be empty list if server has no quotas configured
    assert isinstance(quotas, list)


async def test_uid_expunge(client, test_folder):
    if not await client.has_capability("UIDPLUS"):
        pytest.skip("Server does not support UIDPLUS")

    await _clear_folder(client, test_folder)
    for i in range(3):
        await client.append(
            test_folder,
            "Subject: msg %d\r\n\r\nbody %d\r\n" % (i, i),
        )

    await client.select_folder(test_folder)
    messages = await client.search("ALL")
    assert len(messages) == 3

    # Delete msg 0 and msg 2, but only expunge msg 2
    await client.delete_messages([messages[0], messages[2]])
    await client.expunge(messages[2])

    remaining = await client.search("ALL")
    assert len(remaining) == 2
    assert messages[0] in remaining
    assert messages[1] in remaining


# ---------------------------------------------------------------------------
# Group 10: SocketTimeout
# ---------------------------------------------------------------------------


async def test_socket_timeout_read():
    """Verify that a very small read timeout causes a TimeoutError."""
    client = AsyncIMAPClient(
        _HOST,
        _PORT,
        ssl=True,
        timeout=SocketTimeout(connect=30, read=0.00001),
    )
    await client._imap.connect()
    client._apply_read_timeout()
    # With an absurdly small read timeout, any command should time out
    with pytest.raises((asyncio.TimeoutError, IMAPClientError, OSError)):
        await client.login(_USER, _PASSWORD)


# ---------------------------------------------------------------------------
# Cleanup safety net
# ---------------------------------------------------------------------------


async def test_zzz_final_cleanup():
    """Run last (alphabetically) to clean up any remaining test folders."""
    c = await _make_client()
    try:
        await _cleanup_test_folders(c)
    finally:
        await _quiet_logout(c)
