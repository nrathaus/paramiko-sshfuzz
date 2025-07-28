#!/usr/bin/python3

import random

import getpass

import os
import sys

import struct

import logging
from io import BytesIO

from hexdump import hexdump

# logging.basicConfig(level=logging.DEBUG)
logging.getLogger("paramiko.fuzz").setLevel(logging.INFO)


# If you don't install paramiko, this will allow you to run the python without it
#  makes it easier to debug the code paramiko
file_path = os.path.abspath(".")
sys.path.append(file_path)

import paramiko
import paramiko.fuzz
from paramiko import Message, util

zero_byte = b"\x00"
one_byte = b"\x01"
max_byte = b"\xff"


messages_prototypes = {}


def add_bytes(self, b):
    """
    Write bytes to the stream, without any formatting.

    :param str b: bytes to add
    """

    self.fields.append({"func": "add_bytes", "default": b})
    self.packet.write(b)
    return self


def add_byte(self, b):
    """
    Write a single byte to the stream, without any formatting.

    :param str b: byte to add
    """

    self.fields.append({"func": "add_byte", "default": b})
    self.packet.write(b)
    return self


def add_boolean(self, b):
    """
    Add a boolean value to the stream.

    :param bool b: boolean value to add
    """

    self.fields.append({"func": "add_boolean", "default": b})

    # Disable randomization
    if False and random.choice([False] * 7 + [True]):
        # print(f"Fuzzing add_boolean: {b}")
        b = random.choice(range(2, 0xFF))
        # print(f"Now: {b}")
        self.packet.write(bytes(b))
    else:
        if b:
            self.packet.write(one_byte)
        else:
            self.packet.write(zero_byte)

    return self


def add_int(self, n, direct=True):
    """
    Add an integer to the stream.

    :param int n: integer to add
    :param bool direct: whether the func is called directly or from another add_
    """

    if direct:
        self.fields.append({"func": "add_int", "default": n})

    # Disable randomization
    if False and random.choice([False] * 7 + [True]):
        # print(f"Fuzzing add_int: {n}")
        n = random.choice([0, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000])
        # print(f"Now: {n}")

    new_n = 0
    try:
        new_n = struct.pack(">I", n)
    except Exception as exception:
        print(f"Unable to encode 'n' into int, exception: {exception}")

    self.packet.write(new_n)
    return self


def add_adaptive_int(self, n):
    """
    Add an integer to the stream.

    :param int n: integer to add
    """

    self.fields.append({"func": "add_adaptive_int", "default": n})
    if n >= Message.big_int:
        self.packet.write(max_byte)
        self.add_string(util.deflate_long(n), direct=False)
    else:
        self.packet.write(struct.pack(">I", n))

    return self


def add_int64(self, n):
    """
    Add a 64-bit int to the stream.

    :param long n: long int to add
    """

    self.fields.append({"func": "add_int64", "default": n})
    self.packet.write(struct.pack(">Q", n))
    return self


# Each module, uses its own asbytes - so lets take the one in the common.py
#  before the 'split' between modules


def asbytes(s):
    if not isinstance(s, bytes):
        if isinstance(s, str):
            return util.b(s)

        try:
            s = s.asbytes()
        except Exception:
            raise Exception("Unknown type")

    return s


def add_string(self, s, direct=True):
    """
    Add a string to the stream.

    :param str s: string to add
    :param bool direct: whether the func is called directly or from another add_
    """

    if direct:
        self.fields.append({"func": "add_string", "default": s})

    s = asbytes(s)
    if False and random.choice([False] * 7 + [True]):
        # print(f"Adding to {s} - an int")
        self.add_int(0xFFFFFFFF)
    else:
        self.add_int(len(s), False)

    self.packet.write(s)
    return self


def add_mpint(self, z):
    """
    Add a long int to the stream, encoded as an infinite-precision
    integer.  This method only works on positive numbers.

    :param int z: long int to add
    """
    self.fields.append({"func": "add_mpint", "default": z})
    self.add_string(util.deflate_long(z), direct=False)
    return self


def add_list(self, l):  # noqa: E741
    """
    Add a list of strings to the stream.  They are encoded identically to
    a single string of values separated by commas.  (Yes, really, that's
    how SSH2 does it.)

    :param l: list of strings to add
    """
    self.fields.append({"func": "add_list", "default": l})
    self.add_string(",".join(l), direct=False)
    return self


def _send_message(self, data):
    """
    Override the '_send_message', we want it to ignore the 'add_' calls
      and use the fields in either default state or in their fuzzed state
    """

    if data.name not in messages_prototypes:
        # If we haven't seen this prototype before, add it to the list with the fields at
        #   their default state
        messages_prototypes[data.name] = {
            "done": False,
            "active": False,
            "fields": data.fields.copy(),
        }
    else:
        # If we have seen this prototype before, make sure that the values (default) still match
        messages_prototype = messages_prototypes[data.name]
        stored_fields = messages_prototype["fields"]
        if len(data.fields) != len(stored_fields):
            raise ValueError("This is worrying... there is a mismatch in the len")

        for idx, field in enumerate(data.fields):
            stored_field = stored_fields[idx]
            if stored_field["func"] != field["func"]:
                raise ValueError("This is worrying... there is a func mismatch")

            if stored_field["default"] != field["default"]:
                # If the default value is different now, update the default value
                #  otherwise we can fail, for example in the case of MSG_CHANNEL_OPEN
                #  as the channel_id changes (every close/open) and using the previous
                #  closed channel_id will fail
                stored_field["default"] = field["default"]

        # Now that the default values are known to be ok, we can decide what to fuzz
        if not messages_prototype["done"] and not messages_prototype["active"]:
            # Mark it as being
            messages_prototype["active"] = True

        if messages_prototype["active"]:
            # See if one of the fields can be tested
            found_not_done = False
            for stored_field in stored_fields:
                if not stored_field["done"]:
                    # We need to move it one pos forward and check if it reached
                    #  the max
                    if "pos" not in stored_field:
                        # pos 0 is the default value
                        stored_field["pos"] = 0
                        stored_field["active"] = True
                        break

                    if stored_field["pos"] > stored_field["max"]:
                        stored_field["pos"] = 0
                        stored_field["active"] = False
                        stored_field["done"] = True
                        continue

                    found_not_done = True
                    break

            if not found_not_done:
                messages_prototype["done"] = True

    messages_prototype = messages_prototypes[data.name]

    print(f"{data.name}: {len(messages_prototype['fields'])=}")

    # before = hexdump(data.packet.getvalue(), result="return")

    data.packet = BytesIO()
    for field in messages_prototype["fields"]:
        # field has two values at position:
        #  0 - func
        #  1 - default value
        func_name = field[0]
        default_value = field[1]
        if func_name == "add_byte":
            add_byte(data, default_value)
            continue
        if func_name == "add_bytes":
            add_byte(data, default_value)
            continue
        if func_name == "add_string":
            add_string(data, default_value)
            continue
        if func_name == "add_int":
            add_int(data, default_value)
            continue
        if func_name == "add_boolean":
            add_boolean(data, default_value)
            continue

        # If we fall through the cracks, just write the default value
        raise ValueError("Forgot to define func")

    # Use this 'before' and 'after' matching for 'default' state verification
    #  i.e. no fuzzing should result in before and after working
    # after = hexdump(data.packet.getvalue(), result="return")
    # if after != before:
    #     pass

    self.packetizer.send_message(data)


FuzzMaster = paramiko.fuzz.FuzzMaster
FuzzMaster.MUTATION_PER_RUN = 10000
FuzzMaster.add_fuzzdef("add_byte", add_byte)
FuzzMaster.add_fuzzdef("add_bytes", add_bytes)
FuzzMaster.add_fuzzdef("add_list", add_list)
FuzzMaster.add_fuzzdef("add_string", add_string)
FuzzMaster.add_fuzzdef("add_int", add_int)
FuzzMaster.add_fuzzdef("add_mpint", add_mpint)
FuzzMaster.add_fuzzdef("add_boolean", add_boolean)
FuzzMaster.add_fuzzdef("add_adaptive_int", add_adaptive_int)
FuzzMaster.add_fuzzdef("add_int64", add_int64)
FuzzMaster.add_fuzzdef("_send_message", _send_message)

random.seed(1337)

port = 22

# get hostname
username = ""
if len(sys.argv) > 1:
    hostname = sys.argv[1]
    if hostname.find("@") >= 0:
        username, hostname = hostname.split("@")
else:
    hostname = input("Hostname: ")
if len(hostname) == 0:
    print("*** Hostname required.")
    sys.exit(1)

if hostname.find(":") >= 0:
    hostname, portstr = hostname.split(":")
    port = int(portstr)

# get username
if username == "":
    default_username = getpass.getuser()
    username = input("Username [%s]: " % default_username)
    if len(username) == 0:
        username = default_username

password = getpass.getpass("Password for %s@%s: " % (username, hostname))


client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
for i in range(1000):
    try:
        client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            # Prevent getting hung on anything
            timeout=1,
            banner_timeout=1,
            channel_timeout=1,
            auth_timeout=1,
        )
        _, sout, _ = client.exec_command("whoami")
        print(sout.read())
        print()
        _, sout, _ = client.exec_command("id")
        print(sout.read())
        print()
        client.invoke_shell()
        client.open_sftp()
        transport = client.get_transport()
        session = transport.open_session()
        session.request_x11(auth_cookie="JO")
        session.exec_command("whoami")
    except paramiko.fuzz.StopFuzzing as sf:
        print("STOP FUZZING")

        break


print(f"{messages_prototypes=}")
