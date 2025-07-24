import inspect
import hashlib
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
        self.signatures_func = {}
        self.signatures_invocations = {}
        self.fuzz_methods = {}  # name: func
        self.reset()
        logger.debug("--init--")

    def reset(self):
        self.mutations = 0
        logger.info("--reset--")

    def add_fuzzdef(self, fname, f):
        self.fuzz_methods[fname] = f

    def hash_sig(self, seq):
        incoming_string = "".join(str(e) for e in seq)
        return hashlib.sha256(incoming_string.encode("utf-8")).hexdigest()

    def print_trace(self):
        for x in inspect.stack():
            logger.debug(x)
        logger.debug("-------")

    def candidate(self, f):
        signature = tuple([self.hash_sig(frame) for frame in inspect.stack()])
        self.signatures_func.setdefault(signature, 0)
        logger.info("adding static candidate: %s" % f)
        self.print_trace()

        def mutate_candidate(*args, **kwargs):
            signature = tuple([self.hash_sig(frame) for frame in inspect.stack()])
            self.signatures_invocations.setdefault(signature, 0)
            logger.info("adding dynamic candidate: %s" % f)
            self.print_trace()
            if self.mutations >= self.MUTATION_PER_RUN:
                raise StopFuzzing()
            if (
                f.__name__ in self.fuzz_methods
                and self.signatures_invocations[signature] == 0
                and self.mutations < self.MUTATION_PER_RUN
            ):
                self.mutations += 1
                # mutate
                logger.info(
                    "--WHOOP WHOOP MUTATE! %s - %s" % (f.__name__, repr(signature))
                )
                return self.fuzz_methods[f.__name__](*args, **kwargs)
            return f(*args, **kwargs)

        return mutate_candidate


FuzzMaster = FuzzControl()
logger.info("FuzzControl init.")
