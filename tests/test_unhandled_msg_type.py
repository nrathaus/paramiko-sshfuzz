"""
Tests for the "unhandled message type" fallback in ``Transport.run()``.

``ptype`` comes straight off the wire -- ``Packetizer.read_message()`` returns
whatever byte the peer put in the payload's first octet, and nothing between
there and the dispatch fallback checks it against ``MSG_NAMES``. ``MSG_NAMES``
only maps the ~44 types paramiko knows about, so the fallback used to do::

    name = MSG_NAMES[ptype]

which raised ``KeyError`` for the remaining 200-odd byte values *instead of*
logging the warning and replying with MSG_UNIMPLEMENTED. ``KeyError`` is not an
`SSHException`, so it fell through to the generic ``except Exception`` at the
bottom of ``run()``: the transport thread died and the session was torn down.
A peer could kill any paramiko transport with a single 1-byte packet -- the very
input that branch exists to handle.

These tests pin the fixed behavior: unknown types are answered, not fatal.
"""

import unittest

from paramiko.common import (
    MSG_NAMES,
    MSG_SERVICE_ACCEPT,
    MSG_UNIMPLEMENTED,
    byte_chr,
)
from paramiko.message import Message
from paramiko.sftp import CMD_NAMES, SFTP_OP_UNSUPPORTED
from paramiko.sftp_server import SFTPServer

from ._util import server, wait_until


# Within spec per RFC 4251 (128-191 is "local extensions", 192-255 reserved for
# private use), unknown to paramiko, and therefore absent from MSG_NAMES.
MSG_NOT_IN_MSG_NAMES = 253


class MsgNamesLookupTest(unittest.TestCase):
    """
    Why the fallback cannot use a bare ``MSG_NAMES[ptype]``.
    """

    def test_msg_names_does_not_cover_every_byte_value(self):
        # A message type is a single byte, so anything in range(256) can
        # legitimately arrive on the wire.
        unmapped = [i for i in range(256) if i not in MSG_NAMES]
        # Sanity: the overwhelming majority of byte values are unmapped.
        self.assertGreater(len(unmapped), 200)
        self.assertIn(MSG_NOT_IN_MSG_NAMES, unmapped)

    def test_bare_lookup_would_raise_for_every_unmapped_byte_value(self):
        for ptype in (i for i in range(256) if i not in MSG_NAMES):
            with self.assertRaises(KeyError):
                MSG_NAMES[ptype]


class UnhandledMessageTypeTest(unittest.TestCase):
    """
    End-to-end: an authenticated peer sends one packet with an unmapped type.
    """

    def _send_raw_ptype(self, transport, ptype):
        m = Message()
        m.add_byte(byte_chr(ptype))
        # No body; the dispatch in run() looks at the type byte only.
        transport._send_message(m)

    def _assert_survives_ptype(self, ptype):
        with server(skip_verify=True) as (tc, ts):
            self.assertTrue(ts.is_active())

            self._send_raw_ptype(tc, ptype)

            # Nothing to wait *for* on the happy path, so wait for the failure
            # mode not to happen: before the fix, the server's run() thread
            # died on KeyError well inside this window.
            with self.assertRaises(TimeoutError):
                wait_until(lambda: self.assertFalse(ts.is_active()), timeout=1)

            self.assertTrue(
                ts.is_active(),
                "server died on message type {}: {!r}".format(
                    ptype, ts.get_exception()
                ),
            )
            self.assertIsNone(ts.get_exception())

    def test_unmapped_ptype_does_not_kill_the_transport(self):
        self.assertNotIn(MSG_NOT_IN_MSG_NAMES, MSG_NAMES)
        self._assert_survives_ptype(MSG_NOT_IN_MSG_NAMES)

    def test_mapped_but_unhandled_ptype_does_not_kill_the_transport(self):
        """
        Control case: same code path, with a type MSG_NAMES *does* know.

        MSG_SERVICE_ACCEPT is a client-only message, so a server reaching it
        falls into the same fallback branch. This one always worked; it is here
        so a regression that breaks the branch as a whole is distinguishable
        from one that only breaks the unknown-type lookup.
        """
        self.assertIn(MSG_SERVICE_ACCEPT, MSG_NAMES)
        self._assert_survives_ptype(MSG_SERVICE_ACCEPT)

    def test_unmapped_ptype_is_answered_with_MSG_UNIMPLEMENTED(self):
        # Not just "doesn't crash": the branch's actual job.
        with server(skip_verify=True) as (tc, ts):
            sent = []
            original = ts._send_message

            def spy(msg):
                sent.append(msg.asbytes()[0])
                return original(msg)

            ts._send_message = spy
            try:
                self._send_raw_ptype(tc, MSG_NOT_IN_MSG_NAMES)
                wait_until(
                    lambda: self.assertIn(MSG_UNIMPLEMENTED, sent), timeout=2
                )
            finally:
                ts._send_message = original

            self.assertTrue(ts.is_active())
            # The client does *not* answer back: the `ptype !=
            # MSG_UNIMPLEMENTED` guard on the other end is what keeps this from
            # becoming a ping-pong loop.
            self.assertEqual(sent.count(MSG_UNIMPLEMENTED), 1)


class UnhandledSFTPCommandTest(unittest.TestCase):
    """
    The same defect one layer up: ``SFTPServer._process`` used to log
    ``CMD_NAMES[t]`` for a client-supplied packet type ``t``.

    ``_process`` ends in an ``else`` that answers SFTP_OP_UNSUPPORTED, so
    unknown types are meant to be tolerated -- but the debug log ran first and
    raised ``KeyError``, which ``start_subsystem`` then reported as a generic
    SFTP_FAILURE (plus a logged traceback) rather than SFTP_OP_UNSUPPORTED.
    """

    # SSH_FXP numbers are also single bytes; 250 is not one paramiko knows.
    CMD_NOT_IN_CMD_NAMES = 250

    def _process(self, t):
        """
        Drive ``_process`` with no real channel/server behind it.

        The unknown-type path only touches ``_log`` and ``_send_status``, so
        stubbing those is enough and keeps this off the SFTP fixtures.
        """
        srv = SFTPServer.__new__(SFTPServer)
        statuses = []
        srv._log = lambda level, msg: None
        srv._send_status = lambda rn, code, *a: statuses.append(code)
        srv._process(t, 1, Message())
        return statuses

    def test_cmd_names_does_not_cover_every_byte_value(self):
        self.assertNotIn(self.CMD_NOT_IN_CMD_NAMES, CMD_NAMES)

    def test_unknown_command_gets_OP_UNSUPPORTED(self):
        self.assertEqual(
            self._process(self.CMD_NOT_IN_CMD_NAMES), [SFTP_OP_UNSUPPORTED]
        )
