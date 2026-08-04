"""
Tests for the FuzzControl staging policy and the mutation hot path.

Two things are pinned here:

1. Staging (`freeze_messages`/`arm_only`/`is_armed`). Mutating the handshake
   tears the session down before the channel, subsystem and SFTP layers are
   ever reached, so a harness must be able to hold chosen messages at their
   default values while it fuzzes deeper ones.

2. The hot path never introspects the stack unless TRACE is on. Every
   `Message.add_*` call goes through `candidate()`, and `inspect.stack()` is
   roughly two orders of magnitude more expensive than the primitive it wraps.
"""

import unittest

from paramiko import fuzz as fuzz_module
from paramiko.fuzz import FuzzControl, StopFuzzing


class StagingPolicyTest(unittest.TestCase):
    def setUp(self):
        # A fresh instance, never the process-wide FuzzMaster singleton.
        self.control = FuzzControl()

    def test_everything_armed_by_default(self):
        self.assertTrue(self.control.is_armed("MSG_KEXINIT"))
        self.assertTrue(self.control.is_armed("MSG_CHANNEL_DATA"))

    def test_unnamed_message_is_armed(self):
        # An untagged message should still be fuzzed, not silently skipped.
        self.assertTrue(self.control.is_armed(""))

    def test_freeze_messages_blocks_only_those_names(self):
        self.control.freeze_messages(
            {"MSG_KEXINIT", "MSG_NEWKEYS"}
        )
        self.assertFalse(self.control.is_armed("MSG_KEXINIT"))
        self.assertFalse(self.control.is_armed("MSG_NEWKEYS"))
        self.assertTrue(self.control.is_armed("MSG_CHANNEL_DATA"))

    def test_arm_only_blocks_everything_else(self):
        self.control.arm_only({"MSG_CHANNEL_DATA"})
        self.assertTrue(self.control.is_armed("MSG_CHANNEL_DATA"))
        self.assertFalse(self.control.is_armed("MSG_KEXINIT"))
        self.assertFalse(self.control.is_armed(""))

    def test_arm_only_none_re_arms_everything(self):
        self.control.arm_only({"MSG_CHANNEL_DATA"})
        self.control.arm_only(None)
        self.assertTrue(self.control.is_armed("MSG_KEXINIT"))

    def test_freeze_wins_over_arm_only(self):
        # Being explicitly frozen must beat being explicitly armed, so a
        # blanket arm_only() can't accidentally re-enable the handshake.
        self.control.arm_only({"MSG_KEXINIT"})
        self.control.freeze_messages({"MSG_KEXINIT"})
        self.assertFalse(self.control.is_armed("MSG_KEXINIT"))

    def test_clear_staging_resets_policy(self):
        self.control.freeze_messages({"MSG_KEXINIT"})
        self.control.arm_only({"MSG_CHANNEL_DATA"})
        self.control.clear_staging()
        self.assertTrue(self.control.is_armed("MSG_KEXINIT"))
        self.assertTrue(self.control.is_armed("MSG_CHANNEL_DATA"))


class ExplodingInspect:
    """
    Stand-in for the `inspect` module that fails if stack() is touched.

    Only paramiko.fuzz's own module global is rebound -- patching an attribute
    on the real inspect module would break every other importer, pytest
    included.
    """

    def stack(self, *args, **kwargs):
        raise AssertionError(
            "inspect.stack() was called on the fuzzing hot path"
        )


class HotPathTest(unittest.TestCase):
    def setUp(self):
        self.control = FuzzControl()
        self._real_inspect = fuzz_module.inspect

    def tearDown(self):
        fuzz_module.inspect = self._real_inspect

    def test_decoration_does_not_walk_the_stack(self):
        fuzz_module.inspect = ExplodingInspect()

        @self.control.candidate
        def add_thing(value):
            return value

        self.assertEqual(self.control.signatures_func, {})

    def test_mutating_call_does_not_walk_the_stack(self):
        self.control.MUTATION_PER_RUN = 1000

        @self.control.candidate
        def add_thing(value):
            return value

        self.control.add_fuzzdef("add_thing", lambda value: "mutated")
        fuzz_module.inspect = ExplodingInspect()

        # This is the hot path: registered, armed, actually mutating.
        for _ in range(100):
            self.assertEqual(add_thing("hello"), "mutated")

        self.assertEqual(self.control.mutations, 100)
        self.assertEqual(self.control.signatures_invocations, {})

    def test_unregistered_call_does_not_walk_the_stack(self):
        @self.control.candidate
        def add_thing(value):
            return value

        fuzz_module.inspect = ExplodingInspect()
        self.assertEqual(add_thing("hello"), "hello")
        self.assertEqual(self.control.mutations, 0)

    def test_trace_mode_records_call_sites_stably(self):
        # The signature bookkeeping used to be computed and then thrown away.
        # Under TRACE it must actually accumulate -- and repeated calls from
        # one call site must collapse onto one signature, which only works
        # because frames are keyed on file/line/function rather than on the
        # FrameInfo repr (that embeds a heap address).
        self.control.TRACE = True

        @self.control.candidate
        def add_thing(value):
            return value

        self.control.add_fuzzdef("add_thing", lambda value: "mutated")

        for value in ("a", "b", "c"):
            add_thing(value)  # one call site, three calls

        self.assertEqual(len(self.control.signatures_invocations), 1)
        self.assertEqual(
            list(self.control.signatures_invocations.values()), [3]
        )

    def test_trace_mode_separates_distinct_call_sites(self):
        self.control.TRACE = True

        @self.control.candidate
        def add_thing(value):
            return value

        self.control.add_fuzzdef("add_thing", lambda value: "mutated")

        add_thing("first call site")
        add_thing("second call site")

        self.assertEqual(len(self.control.signatures_invocations), 2)


class CandidateBehaviourTest(unittest.TestCase):
    def setUp(self):
        self.control = FuzzControl()

    def test_candidate_preserves_function_metadata(self):
        # The registry is keyed on __name__, so wrapping must not lose it.
        @self.control.candidate
        def add_string(value):
            """Docstring survives."""
            return value

        self.assertEqual(add_string.__name__, "add_string")
        self.assertEqual(add_string.__doc__, "Docstring survives.")
        self.assertTrue(hasattr(add_string, "__wrapped__"))

    def test_every_registered_call_is_dispatched_to_the_mutator(self):
        # The harness does its own per-field position bookkeeping, so it
        # relies on getting control on *every* call, not just the first per
        # call site.
        seen = []

        @self.control.candidate
        def add_thing(value):
            seen.append(("real", value))
            return value

        self.control.add_fuzzdef(
            "add_thing", lambda value: seen.append(("fake", value))
        )

        for i in range(5):
            add_thing(i)

        self.assertEqual([kind for kind, _ in seen], ["fake"] * 5)
        self.assertEqual(self.control.mutations, 5)

    def test_mutation_budget_still_raises_stop_fuzzing(self):
        self.control.MUTATION_PER_RUN = 2

        @self.control.candidate
        def add_thing(value):
            return value

        self.control.add_fuzzdef("add_thing", lambda value: value)

        add_thing("first")
        add_thing("second")
        self.assertRaises(StopFuzzing, add_thing, "third")


if __name__ == "__main__":
    unittest.main()
