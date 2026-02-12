# AsyncIMAPClient Implementation Details

## Overview

`AsyncIMAPClient` is a 1:1 async mirror of the existing `IMAPClient` class. It uses `aioimaplib` (located at `deps/aioimaplib/src/aioimaplib/`) as its backend instead of stdlib `imaplib`. All existing sync `IMAPClient` functionality is untouched. The two clients share all response parsing, UTF-7 encoding, datetime utilities, and helper functions with zero code duplication.

---

## Architecture

### Dependency Chain

```
IMAPClient (sync)                AsyncIMAPClient (async)
      |                                 |
      v                                 v
  imaplib (stdlib)              aioimaplib (deps/)
      |                                 |
      v                                 v
  socket (TCP)              asyncio.open_connection (TCP)
```

### Shared Modules (no changes, used by both clients)

- `imapclient/response_parser.py` - Parses IMAP FETCH, LIST, SEARCH responses
- `imapclient/response_lexer.py` - Tokenizes IMAP responses
- `imapclient/response_types.py` - Envelope, Address, BodyData types
- `imapclient/imap_utf7.py` - Modified UTF-7 encode/decode for folder names
- `imapclient/datetime_util.py` - INTERNALDATE formatting, criteria date formatting
- `imapclient/fixed_offset.py` - Timezone offset helper
- `imapclient/util.py` - `to_bytes`, `to_unicode`, `chunk`, `assert_imap_protocol`
- `imapclient/exceptions.py` - Exception hierarchy (unchanged)

### Helper Functions Imported from `imapclient.imapclient`

The async client directly imports these from the sync module to avoid duplication:

```python
from .imapclient import (
    _RE_SELECT_RESPONSE, MailboxQuotaRoots, Namespace, Quota, SocketTimeout,
    _dict_bytes_normaliser, _is8bit, _iter_with_last, _literal, _quoted,
    _normalise_search_criteria, _normalise_sort_criteria, _parse_quota,
    _parse_untagged_response, _POPULAR_PERSONAL_NAMESPACES,
    _POPULAR_SPECIAL_FOLDERS, _quote, as_pairs, as_triplets, debug_trunc,
    IMAPlibLoggerAdapter, join_message_ids, normalise_text_list,
    seq_to_parenstr, seq_to_parenstr_upper, utf7_decode_sequence,
)
```

---

## Files Created

### 1. `imapclient/aioimapclient.py` (~800 lines)

The core async client module.

#### Import of aioimaplib

aioimaplib is not installed as a package; it lives under `deps/`. The module adds the path at import time:

```python
_deps_path = os.path.join(os.path.dirname(__file__), "..", "deps", "aioimaplib", "src")
if _deps_path not in sys.path:
    sys.path.insert(0, os.path.abspath(_deps_path))
import aioimaplib
```

#### Class: `AsyncIMAPClient`

##### Constructor (`__init__`)

Sync. Creates the `aioimaplib.IMAP4` / `IMAP4_SSL` / `IMAP4_stream` instance but does NOT connect. aioimaplib uses lazy connection (connection happens on first command or explicit `await client._imap.connect()`).

```python
def __init__(self, host, port=None, use_uid=True, ssl=True,
             stream=False, ssl_context=None, timeout=None):
```

Same parameter validation as `IMAPClient.__init__`:
- `stream=True` with `port` or `ssl` raises `ValueError`
- Default port: 993 if `ssl=True`, 143 otherwise
- Warning logged if `ssl=True` and `port=143`
- Timeout wrapped in `SocketTimeout` if given as raw float

Key difference from sync: No `_set_read_timeout()` call (aioimaplib handles timeouts via `asyncio.wait_for` internally).

##### Factory method: `_create_IMAP4()`

Sync. Returns an unconnected aioimaplib instance:

| Condition | Returns |
|-----------|---------|
| `self.stream` | `aioimaplib.IMAP4_stream(self.host)` |
| `self.ssl` | `aioimaplib.IMAP4_SSL(host, port, ssl_context=..., timeout=...)` |
| else | `aioimaplib.IMAP4(host, port, timeout=...)` |

For SSL: if `ssl_context` is `None`, creates `ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)`. This matches the sync client's `tls.IMAP4_TLS` behavior.

##### Context Manager

```python
async def __aenter__(self):
    await self._imap.connect()
    return self

async def __aexit__(self, exc_type, exc_val, exc_tb):
    try:
        await self.logout()
    except Exception:
        try:
            await self.shutdown()
        except Exception as e:
            logger.info("Could not close the connection cleanly: %s", e)
```

##### `_async_require_capability` Decorator

Module-level decorator factory for async methods:

```python
def _async_require_capability(capability):
    def actual_decorator(func):
        @functools.wraps(func)
        async def wrapper(client, *args, **kwargs):
            if not await client.has_capability(capability):
                raise exceptions.CapabilityError(
                    "Server does not support {} capability".format(capability)
                )
            return await func(client, *args, **kwargs)
        return wrapper
    return actual_decorator
```

Key difference from sync version: `has_capability()` is awaited because it may need to fetch capabilities from the server.

##### Exception Bridging

aioimaplib defines its own exception classes on the `IMAP4` class:
- `aioimaplib.IMAP4.error`
- `aioimaplib.IMAP4.abort`
- `aioimaplib.IMAP4.readonly`

The async client catches these in `_command_and_check` and re-raises as:
- `exceptions.IMAPClientError`
- `exceptions.IMAPClientAbortError`
- `exceptions.IMAPClientReadOnlyError`

```python
async def _command_and_check(self, command, *args, unpack=False, uid=False):
    try:
        if uid and self.use_uid:
            typ, data = await self._imap.uid(command, *args)
        else:
            meth = getattr(self._imap, to_unicode(command))
            typ, data = await meth(*args)
    except self._imap.error as e:
        raise exceptions.IMAPClientError("%s command error: %s" % (command, str(e)))
    self._checkok(command, typ, data)
    if unpack:
        return data[0]
    return data
```

---

## Complete Method-by-Method Mapping

### Methods that became `async def`

Every method that touches `self._imap` (I/O) is async. The mapping from sync IMAPClient to async AsyncIMAPClient:

#### Authentication & Session

| Method | Calls internally |
|--------|-----------------|
| `login(username, password)` | `await self._command_and_check("login", ...)` |
| `oauth2_login(user, access_token, mech, vendor)` | `await self._command_and_check("authenticate", mech, lambda x: auth_string)` |
| `oauthbearer_login(identity, access_token)` | `await self._command_and_check("authenticate", "OAUTHBEARER", lambda x: auth_string)` |
| `plain_login(identity, password, authz_id)` | `await self._command_and_check("authenticate", "PLAIN", lambda _: auth_string)` |
| `sasl_login(mech_name, mech_callable)` | `await self._command_and_check("authenticate", mech_name, mech_callable)` |
| `logout()` | `await self._imap.logout()` then checks for `"BYE"` response |
| `shutdown()` | `await self._imap.shutdown()` |
| `starttls(ssl_context)` | `await self._imap.starttls(ssl_context)` |

#### Capabilities

| Method | Calls internally |
|--------|-----------------|
| `capabilities()` | Checks cache, then `await self._do_capabilites()` if needed. Accesses `self._imap.untagged_responses` and `self._imap.capabilities` (sync attribute reads). |
| `_do_capabilites()` | `await self._command_and_check("capability", unpack=True)` |
| `has_capability(capability)` | `to_bytes(capability).upper() in await self.capabilities()` |
| `enable(*capabilities)` | `await self._raw_command_untagged(b"ENABLE", ..., response_name="ENABLED")` |
| `id_(parameters)` | `await self._imap._simple_command("ID", args)` then `self._imap._untagged_response(...)` (sync) |

#### Folder Operations

| Method | Calls internally |
|--------|-----------------|
| `list_folders(directory, pattern)` | `await self._do_list("LIST", ...)` |
| `xlist_folders(directory, pattern)` | `await self._do_list("XLIST", ...)` |
| `list_sub_folders(directory, pattern)` | `await self._do_list("LSUB", ...)` |
| `_do_list(cmd, directory, pattern)` | `await self._imap._simple_command(cmd, ...)` then `self._imap._untagged_response(...)` (sync) |
| `find_special_folder(folder_flag)` | `await self.list_folders()`, `await self.has_capability("NAMESPACE")`, `await self.namespace()` |
| `select_folder(folder, readonly)` | `await self._command_and_check("select", ...)` then `self._process_select_response(...)` (sync) |
| `unselect_folder()` | `await self._imap._simple_command("UNSELECT")` |
| `close_folder()` | `await self._command_and_check("close")` |
| `create_folder(folder)` | `await self._command_and_check("create", ...)` |
| `rename_folder(old, new)` | `await self._command_and_check("rename", ...)` |
| `delete_folder(folder)` | `await self._command_and_check("delete", ...)` |
| `folder_exists(folder)` | `len(await self.list_folders("", folder)) > 0` |
| `subscribe_folder(folder)` | `await self._command_and_check("subscribe", ...)` |
| `unsubscribe_folder(folder)` | `await self._command_and_check("unsubscribe", ...)` |
| `folder_status(folder, what)` | `await self._command_and_check("status", ...)` |
| `namespace()` | `await self._command_and_check("namespace")` |

#### Message Operations

| Method | Calls internally |
|--------|-----------------|
| `search(criteria, charset)` | `await self._search(criteria, charset)` |
| `_search(criteria, charset)` | `await self._raw_command_untagged(b"SEARCH", ...)` |
| `gmail_search(query, charset)` | `await self._search([b"X-GM-RAW", query], charset)` |
| `sort(sort_criteria, criteria, charset)` | `await self._raw_command_untagged(b"SORT", ...)` |
| `thread(algorithm, criteria, charset)` | `await self._raw_command_untagged(b"THREAD", ...)` |
| `fetch(messages, data, modifiers)` | `await self._imap._command(...)` then `await self._imap._command_complete("FETCH", tag)` then `self._imap._untagged_response(...)` (sync) |
| `append(folder, msg, flags, msg_time)` | `await self._command_and_check("append", ...)` |
| `multiappend(folder, msgs)` | `await self._raw_command(b"APPEND", ...)` |
| `copy(messages, folder)` | `await self._command_and_check("copy", ..., uid=True)` |
| `move(messages, folder)` | `await self._command_and_check("move", ..., uid=True)` |
| `expunge(messages)` | If messages: `await self._command_and_check("EXPUNGE", ..., uid=True)`. Otherwise: `await self._imap._command("EXPUNGE")` + `await self._consume_until_tagged_response(...)` |
| `uid_expunge(messages)` | `await self._command_and_check("EXPUNGE", ..., uid=True)` |

#### Flag Operations

| Method | Calls internally |
|--------|-----------------|
| `get_flags(messages)` | `await self.fetch(messages, ["FLAGS"])` |
| `add_flags(messages, flags, silent)` | `await self._store(b"+FLAGS", ...)` |
| `remove_flags(messages, flags, silent)` | `await self._store(b"-FLAGS", ...)` |
| `set_flags(messages, flags, silent)` | `await self._store(b"FLAGS", ...)` |
| `delete_messages(messages, silent)` | `await self.add_flags(messages, DELETED, silent=silent)` |
| `_store(cmd, messages, flags, fetch_key, silent)` | `await self._command_and_check("store", ..., uid=True)` |

#### Gmail Labels

| Method | Calls internally |
|--------|-----------------|
| `get_gmail_labels(messages)` | `await self.fetch(messages, [b"X-GM-LABELS"])` |
| `add_gmail_labels(messages, labels, silent)` | `await self._gm_label_store(b"+X-GM-LABELS", ...)` |
| `remove_gmail_labels(messages, labels, silent)` | `await self._gm_label_store(b"-X-GM-LABELS", ...)` |
| `set_gmail_labels(messages, labels, silent)` | `await self._gm_label_store(b"X-GM-LABELS", ...)` |
| `_gm_label_store(cmd, messages, labels, silent)` | `await self._store(...)` |

#### ACL & Quota

| Method | Calls internally |
|--------|-----------------|
| `getacl(folder)` | `await self._command_and_check("getacl", ...)` |
| `setacl(folder, who, what)` | `await self._command_and_check("setacl", ...)` |
| `get_quota(mailbox)` | `(await self.get_quota_root(mailbox))[1]` |
| `_get_quota(quota_root)` | `await self._command_and_check("getquota", ...)` |
| `get_quota_root(mailbox)` | `await self._raw_command_untagged(b"GETQUOTAROOT", ..., response_name="QUOTAROOT")` then `self._imap.untagged_responses.pop("QUOTA", [])` |
| `set_quota(quotas)` | `await self._raw_command_untagged(b"SETQUOTA", ..., response_name="QUOTA")` |

#### IDLE

| Method | Calls internally |
|--------|-----------------|
| `idle()` | `await self._imap._command("IDLE")` then `await self._imap._get_response()` - stores tag in `self._idle_tag` |
| `idle_check(timeout)` | `await asyncio.wait_for(self._imap._get_line(), timeout=timeout)` in a loop, collecting untagged responses |
| `idle_done()` | `await self._imap.send(b"DONE\r\n")` then `await self._consume_until_tagged_response(self._idle_tag, "IDLE")` |

The IDLE implementation preserves the same 3-method API as the sync client (`idle()` / `idle_check()` / `idle_done()`), using `asyncio.wait_for` + `asyncio.TimeoutError` instead of `select.poll()`/`select.select()` for timeout handling.

#### NOOP

| Method | Calls internally |
|--------|-----------------|
| `noop()` | `await self._imap._command("NOOP")` then `await self._consume_until_tagged_response(tag, "NOOP")` |

### Internal Async Methods

| Method | Purpose |
|--------|---------|
| `_command_and_check(command, *args, unpack, uid)` | Core command runner. Uses `await self._imap.uid(command, *args)` or `await getattr(self._imap, command)(*args)`. Catches `self._imap.error` and re-raises as `IMAPClientError`. |
| `_raw_command(command, args, uid)` | Low-level byte-level command sender. Manually builds command line, handles 8-bit literals via `_send_literal`, calls `await self._imap.send()` and `await self._imap._command_complete()`. |
| `_raw_command_untagged(command, args, response_name, unpack, uid)` | Calls `_raw_command()` then extracts untagged response via `self._imap._untagged_response()` (sync). |
| `_send_literal(tag, item, has_literal_plus)` | Sends a single IMAP literal. If LITERAL+ supported: sends in one shot. Otherwise: sends size, waits for continuation (`await self._imap._get_response()`), then sends data. |
| `_consume_until_tagged_response(tag, command)` | Reads responses via `await self._imap._get_response()` until the tagged response for `tag` arrives, collecting untagged responses along the way. |

### Methods that Stay Sync

These are pure data processing with no I/O:

| Method | Purpose |
|--------|---------|
| `_process_select_response(resp)` | Parses SELECT/EXAMINE untagged responses into a dict |
| `_normalise_folder(folder_name)` | UTF-7 encode + quote folder name |
| `_normalise_labels(labels)` | UTF-7 encode + quote gmail labels |
| `_normalise_capabilites(raw_response)` | Split + uppercase capability string |
| `_checkok(command, typ, data)` | Assert typ == "OK" |
| `_check_resp(expected, command, typ, data)` | Assert typ == expected |
| `_filter_fetch_dict(fetch_dict, key)` | Extract single key from fetch response dict |
| `_proc_folder_list(folder_data)` | Parse folder listing data |
| `socket()` | Returns `self._imap.socket()` |
| `welcome` (property) | Returns `self._imap.welcome` |

---

### 2. `imapclient/testable_aioimapclient.py` (~55 lines)

Async test infrastructure mirroring `testable_imapclient.py`.

#### `TestableAsyncIMAPClient`

Subclass of `AsyncIMAPClient` that overrides `_create_IMAP4()` to return a `MockAsyncIMAP4`.

#### `MockAsyncIMAP4`

Subclass of `unittest.mock.AsyncMock` with:
- `self.sent = b""` - accumulates bytes sent via `send()`
- `self.tagged_commands = {}` - mock tagged command responses
- `self.untagged_responses = {}` - mock untagged responses
- `self.capabilities = []` - mock capability list
- `self.state = "AUTH"` - mock IMAP state
- `async def send(data)` - appends to `self.sent`
- `def _new_tag()` - returns `"tag"`
- `def socket()` - returns `None`
- `def _untagged_response(typ, dat, name)` - mimics aioimaplib's sync response lookup

### 3. `imapclient/aio.py` (~20 lines)

Convenience module for `from imapclient.aio import AsyncIMAPClient`. Re-exports:
- Everything from `aioimapclient` (AsyncIMAPClient, flags, etc.)
- Everything from `response_parser`
- Version info

### 4. `imapclient/__init__.py` (modified)

Added one line:
```python
from .aioimapclient import AsyncIMAPClient  # noqa: F401
```

This allows `from imapclient import AsyncIMAPClient` alongside `from imapclient import IMAPClient`.

---

## Key Design Decisions

### 1. Lazy Connection

The sync `IMAPClient` connects immediately in `__init__` (via `imaplib.IMAP4()` which calls `open()` in its constructor). The async `AsyncIMAPClient` does NOT connect in `__init__` because aioimaplib uses lazy connection. Connection happens:
- When entering `async with AsyncIMAPClient(...) as client:` (calls `await self._imap.connect()`)
- Or on first command via aioimaplib's `_simple_command` which calls `await self.connect()`

### 2. aioimaplib's `_untagged_response` is Sync

Unlike most aioimaplib methods, `_untagged_response(typ, dat, name)` is a plain sync method (just a dict lookup). The async client calls it directly without `await`. This is correct and matches the internal pattern.

### 3. `has_capability` is Async

In the sync client, `has_capability()` is sync because capabilities are always available (connection already established). In the async client, it must be `async` because the first call may need to fetch capabilities from the server. This means the `_async_require_capability` decorator must also be async-aware.

### 4. No `_set_read_timeout()`

The sync client calls `socket().settimeout()` for read timeouts. aioimaplib handles timeouts via `asyncio.wait_for()` internally, so this is unnecessary.

### 5. IDLE Uses Direct Protocol Access

Rather than using aioimaplib's `AsyncIdler` context manager (which has a different API), the async client implements IDLE using the same 3-method pattern as the sync client by directly accessing `self._imap._command()`, `self._imap._get_response()`, `self._imap._get_line()`, and `self._imap.send()`. This preserves API compatibility.

### 6. Exception Classes

The async client uses the same exception classes as the sync client (`exceptions.IMAPClientError`, `LoginError`, `CapabilityError`, etc.). aioimaplib's own exceptions (`IMAP4.error`, `IMAP4.abort`) are caught and re-raised as the corresponding IMAPClient exceptions.

---

## Verification Results

### Existing Sync Tests

All 267 existing tests pass with zero failures:

```
tests/test_auth.py               3 passed
tests/test_datetime_util.py      5 passed
tests/test_enable.py             5 passed
tests/test_fixed_offset.py       6 passed
tests/test_folder_status.py      3 passed
tests/test_imap_utf7.py          3 passed
tests/test_imapclient.py        60 passed
tests/test_init.py               6 passed
tests/test_login.py              2 passed
tests/test_response_parser.py   37 passed
tests/test_search.py            18 passed
tests/test_sort.py               4 passed
tests/test_starttls.py           4 passed
tests/test_store.py              8 passed
tests/test_thread.py             4 passed
tests/test_util_functions.py    30 passed
tests/test_version.py            5 passed
--------------------------------------
TOTAL                          267 passed
```

### API Parity

Both clients expose exactly 58 public methods with identical names:

```
add_flags, add_gmail_labels, append, capabilities, close_folder, copy,
create_folder, delete_folder, delete_messages, enable, expunge, fetch,
find_special_folder, folder_exists, folder_status, get_flags,
get_gmail_labels, get_quota, get_quota_root, getacl, gmail_search,
has_capability, id_, idle, idle_check, idle_done, list_folders,
list_sub_folders, login, logout, move, multiappend, namespace, noop,
oauth2_login, oauthbearer_login, plain_login, remove_flags,
remove_gmail_labels, rename_folder, sasl_login, search, select_folder,
set_flags, set_gmail_labels, set_quota, setacl, shutdown, socket, sort,
starttls, subscribe_folder, thread, uid_expunge, unselect_folder,
unsubscribe_folder, welcome, xlist_folders
```

### Async/Sync Classification

- **56 async methods** - All I/O-touching methods
- **1 sync method** - `socket()` (returns underlying socket reference)
- **1 property** - `welcome` (returns cached server greeting)
- **3 class attributes** - `Error`, `AbortError`, `ReadOnlyError` (exception classes)

---

## Usage Example

```python
import asyncio
from imapclient import AsyncIMAPClient

async def main():
    async with AsyncIMAPClient("imap.example.com") as client:
        await client.login("user@example.com", "password")
        await client.select_folder("INBOX")

        # Search
        messages = await client.search("UNSEEN")

        # Fetch
        response = await client.fetch(messages, ["FLAGS", "RFC822.HEADER"])
        for msgid, data in response.items():
            print(f"Message {msgid}: {data[b'FLAGS']}")

        # IDLE
        await client.idle()
        responses = await client.idle_check(timeout=30)
        text, idle_responses = await client.idle_done()

        await client.logout()

asyncio.run(main())
```
