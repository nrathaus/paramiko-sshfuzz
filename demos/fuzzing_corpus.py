#!/usr/bin/python3

import random

import getpass

import os
import sys

import struct

import logging
from io import BytesIO

# from hexdump import hexdump

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

# Field struct:
#  {"func": "add_bytes", "default": b, "done": False, "max": 4, "pos": 0}
# 'func': the function that is called for this field
# 'default': the default value for this field (i.e. pos == -1)
# 'done': whether this field has been completely tested or not
# 'max': how many non-default positions do we have?
# 'pos': the position currently being sent, 0 being default value, non-0 fuzzing


def add_bytes(self, b, field=None):
    """
    Write bytes to the stream, without any formatting.

    :param str b: bytes to add
    """

    if field is None:
        self.fields.append(
            {"func": "add_bytes", "default": b, "done": False, "max": 5, "pos": 0}
        )

    new_b = b
    if field is not None and field["pos"] > 0:
        # Send non-default
        if field["pos"] == 1:
            # Send all 0x00
            new_b = bytes([0] * len(b))
        elif field["pos"] == 2:
            # Send all 0xFF
            new_b = bytes([0xFF] * len(b))
        elif field["pos"] == 3:
            # Send nothing
            new_b = bytes(0)
        elif field["pos"] == 4:
            # Send len-1
            new_b = b[0:-1]
        elif field["pos"] == 5:
            # Send len+1
            new_b = b + b"\x00"
        else:
            raise ValueError("Incorrect 'max' value")

    self.packet.write(new_b)
    return self


def add_byte(self, b, field=None):
    """
    Write a single byte to the stream, without any formatting.

    :param str b: byte to add
    """

    if field is None:
        self.fields.append(
            {"func": "add_byte", "default": b, "done": False, "max": 5, "pos": 0}
        )

    new_b = b
    if field is not None and field["pos"] > 0:
        # Send non-default
        if field["pos"] == 1:
            # Send all 0x00
            new_b = bytes([0])
        elif field["pos"] == 2:
            # Send all 0xFF
            new_b = bytes([0xFF])
        elif field["pos"] == 3:
            # Send nothing
            new_b = bytes(0)
        elif field["pos"] == 4:
            # Send len+1
            new_b = b + b"\x00"
        elif field["pos"] == 5:
            # negate / bit flip
            new_b = bytes((~b[0]) & 0xFF)
        else:
            raise ValueError("Incorrect 'max' value")

    self.packet.write(new_b)
    return self


def add_boolean(self, b, field=None):
    """
    Add a boolean value to the stream.

    :param bool b: boolean value to add
    """

    if field is None:
        self.fields.append(
            {"func": "add_boolean", "default": b, "done": False, "max": 1, "pos": 0}
        )

    if field is not None and field["pos"] > 0:
        if field["pos"] == 1:
            # Flip the boolean
            if b:
                self.packet.write(zero_byte)
            else:
                self.packet.write(one_byte)
        else:
            raise ValueError("Incorrect 'max' value")
    else:
        if b:
            self.packet.write(one_byte)
        else:
            self.packet.write(zero_byte)

    return self


def add_int(self, n, field=None, direct=True):
    """
    Add an !unsigned! integer to the stream.

    :param int n: integer to add
    :param bool direct: whether the func is called directly or from another add_
    """

    if field is None and direct:
        self.fields.append(
            {"func": "add_int", "default": n, "done": False, "max": 4, "pos": 0}
        )

    if field is not None and field["pos"] > 0:
        if field["pos"] == 1:
            # min
            n = 0
        elif field["pos"] == 2:
            # max
            n = 0xFFFFFFFF
        elif field["pos"] == 3:
            # half positive
            n = 0x7FFFFFFF
        elif field["pos"] == 4:
            # half negative
            n = 0x80000000
        else:
            raise ValueError("Incorrect 'max' value")

    new_n = 0
    try:
        new_n = struct.pack(">I", n)
    except Exception as exception:
        print(f"add_int - Unable to encode 'n' into int, exception: {exception}")

    self.packet.write(new_n)
    return self


def add_adaptive_int(self, n, field=None):
    """
    Add an integer to the stream.

    :param int n: integer to add
    """

    if field is None:
        self.fields.append({"func": "add_adaptive_int", "default": n, "done": False})

    if n >= Message.big_int:
        self.packet.write(max_byte)
        self.add_string(util.deflate_long(n), field, direct=False)
    else:
        self.packet.write(struct.pack(">I", n))

    return self


def add_int64(self, n, field=None):
    """
    Add a 64-bit int to the stream.

    :param long n: long int to add
    """

    self.fields.append({"func": "add_int64", "default": n, "done": False})
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


def add_string(self, s, field=None, direct=True):
    """
    Add a string to the stream.

    :param str s: string to add
    :param bool direct: whether the func is called directly or from another add_
    """

    if field is None and direct:
        self.fields.append(
            {"func": "add_string", "default": s, "done": False, "max": 7, "pos": 0}
        )

    s = asbytes(s)
    new_s = s
    if field is not None and field["pos"] > 0:
        if field["pos"] == 1:
            # Put len-1
            new_len = len(s) - 1
            if new_len < 0:
                # add_int is "">I" - unsigned int
                new_len = 0
            self.add_int(new_len, field=None, direct=False)
        elif field["pos"] == 2:
            # Put len+1
            self.add_int(len(s) + 1, field=None, direct=False)
        elif field["pos"] == 3:
            # Put 0
            self.add_int(0, field=None, direct=False)
        elif field["pos"] == 4:
            # Make string way longer
            new_s = asbytes(bytes([0x25, 0x6E] * 65535))
            self.add_int(len(new_s), field=None, direct=False)
        elif field["pos"] == 5:
            # Make string way longer
            new_s = asbytes(bytes([0x41] * 65535))
            self.add_int(len(new_s), field=None, direct=False)
        elif field["pos"] == 6:
            # Send half the string
            half_length = round(-1 * (len(s) / 2))
            new_s = asbytes(s[:half_length])
            self.add_int(len(new_s), field=None, direct=False)
        elif field["pos"] == 7:
            # Send length, without the string
            self.add_int(len(new_s), field=None, direct=False)
            new_s = asbytes(bytes())
        else:
            raise ValueError("Incorrect 'max'")
    else:
        self.add_int(len(new_s), field=None, direct=False)

    self.packet.write(new_s)
    return self


def add_mpint(self, z, field=None):
    """
    Add a long int to the stream, encoded as an infinite-precision
    integer.  This method only works on positive numbers.

    :param int z: long int to add
    """
    self.fields.append({"func": "add_mpint", "default": z, "done": False})

    self.add_string(util.deflate_long(z), field, direct=False)
    return self


def add_list(self, l, field=None):
    """
    Add a list of strings to the stream.  They are encoded identically to
    a single string of values separated by commas.  (Yes, really, that's
    how SSH2 does it.)

    :param l: list of strings to add
    """
    if field is None:
        self.fields.append(
            {"func": "add_list", "default": l, "done": False, "max": 2, "pos": 0}
        )

    if field is not None and field["pos"] > 0:
        if field["pos"] == 1:
            # Put just the delimiter
            self.add_string(",", field, direct=False)
        if field["pos"] == 2:
            # Put just the delimiter with an empty value
            self.add_string(",,", field, direct=False)
    else:
        self.add_string(",".join(l), field, direct=False)

    return self


def _send_message(self, data=None):
    """
    Override the '_send_message', we want it to ignore the 'add_' calls
      and use the fields in either default state or in their fuzzed state
    """

    if data is None:
        return

    messages_prototype = {}
    if data.name not in messages_prototypes:
        # If we haven't seen this prototype before, add it to the list with the fields at
        #   their default state
        messages_prototypes[data.name] = {
            "done": False,
            "active": False,
            "fields": data.fields.copy(),
        }
        messages_prototype = messages_prototypes[data.name]
        stored_fields = messages_prototype["fields"]
    else:
        # If we have seen this prototype before, make sure that the values (default) still match
        messages_prototype = messages_prototypes[data.name]
        stored_fields = messages_prototype["fields"]
        if len(data.fields) != len(stored_fields):
            raise ValueError("This is worrying... there is a mismatch in the len")

        for idx, field in enumerate(data.fields):
            stored_field = stored_fields[idx]
            if "done" not in stored_field:
                stored_field["done"] = False

            if "active" not in stored_field:
                stored_field["active"] = False

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
                if "max" not in stored_field:
                    msg = f"A 'max' value should be given for a {stored_field=}"
                    raise ValueError(msg)

                if "done" not in stored_field:
                    stored_field["done"] = False

                if "active" not in stored_field:
                    stored_field["active"] = False

                if not stored_field["done"] and not stored_field["active"]:
                    # pos 0 is the default value
                    stored_field["pos"] = 0
                    stored_field["active"] = True
                    found_not_done = True
                    break

                stored_field["pos"] += 1
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

    # print(f"{data.name}: {len(messages_prototype['fields'])=}")

    # before = hexdump(data.packet.getvalue(), result="return")

    data.packet = BytesIO()
    for field in messages_prototype["fields"]:
        # field has two values at position:
        #  0 - func
        #  1 - default value
        func_name = field["func"]
        default_value = field["default"]
        if "active" in field and field["active"]:
            print(f"{data.name} - {field=}")

        if func_name == "add_byte":
            add_byte(data, default_value, field=field)
            continue
        if func_name == "add_bytes":
            add_bytes(data, default_value, field=field)
            continue
        if func_name == "add_string":
            add_string(data, default_value, field=field)
            continue
        if func_name == "add_int":
            add_int(data, default_value, field=field)
            continue
        if func_name == "add_boolean":
            add_boolean(data, default_value, field=field)
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
FuzzMaster.MUTATION_PER_RUN = 1000000000000
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


while True:
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
        whoami = sout.read()
        # print(f"whoami: {whoami}")
        # print()
        _, sout, _ = client.exec_command("id")
        id = sout.read()
        # print(f"id: {id}")
        # print()
        client.invoke_shell()
        client.open_sftp()
        transport = client.get_transport()
        session = transport.open_session()
        session.request_x11(auth_cookie="JO")
        session.exec_command("whoami")
        client.close()
    except (paramiko.SSHException, EOFError, AssertionError) as exception:
        pass
    except paramiko.fuzz.StopFuzzing as sf:
        print("STOP FUZZING")

        break
    # except Exception as exception:
    # print(f"An SSH exception has occurred: {exception}")

    messages_prototype_done = 0
    tested_fields = 0
    different_fuzzed_values = 0
    for name, messages_prototype in messages_prototypes.items():
        if messages_prototype["done"]:
            messages_prototype_done += 1
            for messages_prototype_field in messages_prototype["fields"]:
                if messages_prototype_field["done"]:
                    tested_fields += 1
                    different_fuzzed_values += messages_prototype_field["max"]

    print(
        f"{messages_prototype_done=} out of {len(messages_prototypes)}, "
        f"{different_fuzzed_values=}, {tested_fields=}"
    )

    if messages_prototype_done == len(messages_prototypes):
        print("Done fuzzing")
        break


print(f"{messages_prototypes=}")
