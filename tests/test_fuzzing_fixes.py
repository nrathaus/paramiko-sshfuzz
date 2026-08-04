"""
Regression tests for the fuzzing-harness-related fixes:

- ``Message.__init__`` accepts a default ``name`` again.
- ``Packetizer.send_message`` silently skips empty payloads instead of
  crashing (deliberately not responding is a valid fuzzing case).
- ``Packetizer._check_keepalive`` no longer kills idle connections that
  never configured keepalives, but still bails out of a rekey that never
  completes.
- ``paramiko.fuzz.FuzzControl.candidate`` skips its expensive stack
  introspection for methods nobody registered to fuzz.
"""

import socket
import unittest
from unittest.mock import patch

from paramiko import Message, Packetizer, util
from paramiko.fuzz import FuzzControl, StopFuzzing

from ._loop import LoopSocket


class MessageDefaultNameTest(unittest.TestCase):
    def test_message_can_be_constructed_with_no_args(self):
        # Before the fix, Message() raised:
        #   TypeError: __init__() missing 1 required positional argument: 'name'
        msg = Message()
        self.assertEqual(msg.name, "")
        msg.add_int(1)
        self.assertEqual(msg.asbytes(), b"\x00\x00\x00\x01")


class PacketizerFixesTest(unittest.TestCase):
    def _make_packetizer(self):
        # __init__ stamps __keepalive_last with time.time(), so callers
        # that care about a consistent fake clock must construct the
        # Packetizer from *within* their "paramiko.packet.time.time" patch,
        # not before it.
        p = Packetizer(LoopSocket())
        p.set_log(util.get_logger("paramiko.transport"))
        return p

    def test_send_message_empty_payload_is_noop(self):
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(wsock)
        p.set_log(util.get_logger("paramiko.transport"))

        # An empty Message serializes to zero bytes. This must not raise,
        # and must not put anything on the wire.
        empty = Message()
        p.send_message(empty)  # should not raise

        rsock.settimeout(0.1)
        self.assertRaises(socket.timeout, rsock.recv, 100)

    def test_check_keepalive_noop_when_never_configured(self):
        # The vast majority of paramiko connections never call
        # set_keepalive(). _check_keepalive() must never raise for them,
        # no matter how long they've been idle.
        fake_now = [1000.0]
        with patch("paramiko.packet.time.time", lambda: fake_now[0]):
            p = self._make_packetizer()
            p._Packetizer__block_engine_out = object()  # pretend we're encrypting

            for _ in range(10):
                p._check_keepalive()  # must not raise
                fake_now[0] += 1.0  # simulate 10 seconds passing

    def test_check_keepalive_noop_before_encrypting(self):
        fake_now = [1000.0]
        with patch("paramiko.packet.time.time", lambda: fake_now[0]):
            p = self._make_packetizer()
            # __block_engine_out defaults to None: connection hasn't
            # started encrypting yet.
            for _ in range(10):
                p._check_keepalive()  # must not raise
                fake_now[0] += 1.0

    def test_check_keepalive_tolerates_brief_rekey(self):
        fake_now = [1000.0]
        with patch("paramiko.packet.time.time", lambda: fake_now[0]):
            p = self._make_packetizer()
            p._Packetizer__block_engine_out = object()
            p._Packetizer__need_rekey = True

            # Under the 5s grace period: no exception yet.
            for _ in range(4):
                p._check_keepalive()
                fake_now[0] += 1.0

    def test_check_keepalive_raises_on_stuck_rekey(self):
        # This is the case the original "prevent endless loop on rekey
        # that never happens" fix was meant to guard -- and it must do so
        # whether or not keepalives are configured, since demos/tests
        # calling paramiko never call set_keepalive() themselves.
        fake_now = [1000.0]
        with patch("paramiko.packet.time.time", lambda: fake_now[0]):
            p = self._make_packetizer()
            p._Packetizer__block_engine_out = object()
            p._Packetizer__need_rekey = True

            for _ in range(4):
                p._check_keepalive()
                fake_now[0] += 1.0
            fake_now[0] += 2.0  # now past the 5s grace period
            self.assertRaises(EOFError, p._check_keepalive)

    def test_check_keepalive_fires_configured_callback(self):
        calls = []
        fake_now = [1000.0]
        with patch("paramiko.packet.time.time", lambda: fake_now[0]):
            p = self._make_packetizer()
            p._Packetizer__block_engine_out = object()
            p.set_keepalive(5, lambda: calls.append(True))

            p._check_keepalive()  # interval hasn't elapsed yet
            self.assertEqual(calls, [])

            fake_now[0] += 6.0
            p._check_keepalive()
            self.assertEqual(calls, [True])


class FuzzControlCandidateTest(unittest.TestCase):
    def setUp(self):
        # Use a fresh instance rather than the process-wide FuzzMaster
        # singleton, so this test can't interfere with (or be interfered
        # with by) anything else touching paramiko.fuzz.FuzzMaster.
        self.control = FuzzControl()

    def test_unregistered_method_skips_introspection_and_runs_normally(self):
        calls = []

        @self.control.candidate
        def add_thing(value):
            calls.append(value)
            return value

        result = add_thing("hello")

        self.assertEqual(result, "hello")
        self.assertEqual(calls, ["hello"])
        # Nothing registered to fuzz "add_thing", so the expensive
        # signature bookkeeping must never have run.
        self.assertEqual(self.control.signatures_invocations, {})
        self.assertEqual(self.control.mutations, 0)

    def test_registered_method_gets_mutated(self):
        calls = []

        @self.control.candidate
        def add_thing(value):
            calls.append(("real", value))
            return value

        def fake_add_thing(value):
            calls.append(("fake", value))
            return "mutated"

        self.control.add_fuzzdef("add_thing", fake_add_thing)

        result = add_thing("hello")

        self.assertEqual(result, "mutated")
        self.assertEqual(calls, [("fake", "hello")])
        self.assertEqual(self.control.mutations, 1)

    def test_registered_method_stops_after_mutation_budget(self):
        self.control.MUTATION_PER_RUN = 1

        @self.control.candidate
        def add_thing(value):
            return value

        self.control.add_fuzzdef("add_thing", lambda value: value)

        add_thing("first")  # consumes the only mutation slot
        self.assertRaises(StopFuzzing, add_thing, "second")


if __name__ == "__main__":
    unittest.main()
