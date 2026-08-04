import functools
import hashlib
import inspect
import logging


class StopFuzzing(Exception):
    pass


logger = logging.getLogger("paramiko.fuzz")


class FuzzControl(object):
    def __init__(self):
        self.MUTATE_INT = True
        self.MUTATE_STR = True
        self.MUTATE_BYTE = True
        self.MUTATION_PER_RUN = 5
        # Per-call stack introspection is ~200x slower than the primitives it
        # wraps, so it is opt-in. Turn it on only when debugging which call
        # site a mutation came from.
        self.TRACE = False
        self.signatures_func = {}
        self.signatures_invocations = {}
        self.fuzz_methods = {}  # name: func
        # Staging policy: which message names may currently be mutated.
        # Mutating the handshake destroys the session before the channel and
        # subsystem layers are ever reached, so a harness needs to be able to
        # hold parts of the protocol at their default values.
        self._frozen_messages = set()
        self._armed_messages = None  # None = everything not frozen is armed
        self.reset()
        logger.debug("--init--")

    def reset(self):
        self.mutations = 0
        logger.info("--reset--")

    def add_fuzzdef(self, fname, f):
        self.fuzz_methods[fname] = f

    # ------------------------------------------------------------------
    # Staging policy
    #
    # A harness drives these; `is_armed()` is the question it asks before
    # advancing a field to its next mutation position. Keeping the handshake
    # frozen while fuzzing deeper messages is what makes the channel,
    # subsystem and SFTP layers reachable at all.
    # ------------------------------------------------------------------

    def freeze_messages(self, names):
        """
        Never mutate these message names; always send their default values.

        Recording still happens, so a harness keeps discovering the fields of
        a frozen message -- it just does not perturb them.
        """
        self._frozen_messages = set(names)
        logger.info("frozen messages: %s", sorted(self._frozen_messages))

    def arm_only(self, names):
        """
        Mutate *only* these message names, leaving everything else at its
        defaults. Pass None to arm everything that is not frozen.
        """
        self._armed_messages = None if names is None else set(names)
        logger.info(
            "armed messages: %s",
            "<all>" if self._armed_messages is None
            else sorted(self._armed_messages),
        )

    def clear_staging(self):
        """Drop any freeze/arm policy: everything is mutable again."""
        self._frozen_messages = set()
        self._armed_messages = None

    def is_armed(self, message_name):
        """
        Whether `message_name` may currently be mutated.

        Unnamed messages (name == "") are treated as armed so that an
        untagged message is still fuzzed rather than silently skipped.
        """
        if message_name in self._frozen_messages:
            return False
        if self._armed_messages is None:
            return True
        return message_name in self._armed_messages

    def hash_sig(self, seq):
        incoming_string = "".join(str(e) for e in seq)
        return hashlib.sha256(incoming_string.encode("utf-8")).hexdigest()

    @staticmethod
    def _frame_key(frame_info):
        """
        A stable identity for one stack frame.

        Hashing the FrameInfo itself does not work: its repr embeds
        `<frame at 0x...>`, so the same call site hashes differently on every
        call and no two signatures ever compare equal.
        """
        return "%s:%s:%s" % (
            frame_info.filename,
            frame_info.lineno,
            frame_info.function,
        )

    def _stack_keys(self):
        # stack(0) skips reading source context lines, which is most of the
        # cost of inspect.stack().
        return tuple(self._frame_key(fi) for fi in inspect.stack(0))

    def print_trace(self):
        for key in self._stack_keys():
            logger.debug(key)
        logger.debug("-------")

    def _record_signature(self):
        """
        Note the current call site. Only used when TRACE is on: the result is
        purely diagnostic, so it must never run on the hot path.
        """
        signature = self.hash_sig(self._stack_keys())
        self.signatures_invocations[signature] = (
            self.signatures_invocations.get(signature, 0) + 1
        )
        return signature

    def candidate(self, f):
        # NB: no stack walk at decoration time. This runs at import for every
        # decorated primitive, and the result was only ever written to a dict
        # that nothing read back.
        if self.TRACE:
            logger.info("adding static candidate: %s", f)

        name = f.__name__

        @functools.wraps(f)
        def mutate_candidate(*args, **kwargs):
            fuzzer = self.fuzz_methods.get(name)
            if fuzzer is None:
                # Nothing registered to fuzz this method: normal, non-fuzzing
                # use of paramiko must not pay for any of the below.
                return f(*args, **kwargs)

            if self.mutations >= self.MUTATION_PER_RUN:
                raise StopFuzzing()

            if self.TRACE:
                signature = self._record_signature()
                logger.info("--WHOOP WHOOP MUTATE! %s - %s", name, signature)
                self.print_trace()

            self.mutations += 1
            return fuzzer(*args, **kwargs)

        return mutate_candidate


FuzzMaster = FuzzControl()
logger.info("FuzzControl init.")
