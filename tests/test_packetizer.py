# Copyright (C) 2003-2009  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Some unit tests for the ssh2 protocol in Transport.
"""

import sys
import unittest
from hashlib import sha1

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

from paramiko import Message, Packetizer, util
from paramiko.common import byte_chr, zero_byte

from ._loop import LoopSocket


x55 = byte_chr(0x55)
x1f = byte_chr(0x1F)


class PacketizerTest(unittest.TestCase):
    def test_write(self):
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(wsock)
        p.set_log(util.get_logger("paramiko.transport"))
        p.set_hexdump(True)
        encryptor = Cipher(
            algorithms.AES(zero_byte * 16),
            modes.CBC(x55 * 16),
            backend=default_backend(),
        ).encryptor()
        p.set_outbound_cipher(encryptor, 16, sha1, 12, x1f * 20)

        # message has to be at least 16 bytes long, so we'll have at least one
        # block of data encrypted that contains zero random padding bytes
        m = Message('')
        m.add_byte(byte_chr(100))
        m.add_int(100)
        m.add_int(1)
        m.add_int(900)
        p.send_message(m)
        data = rsock.recv(100)
        # 32 + 12 bytes of MAC = 44
        self.assertEqual(44, len(data))
        self.assertEqual(
            b"\x43\x91\x97\xbd\x5b\x50\xac\x25\x87\xc2\xc4\x6b\xc7\xe9\x38\xc0",  # noqa
            data[:16],
        )

    def test_read(self):
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(rsock)
        p.set_log(util.get_logger("paramiko.transport"))
        p.set_hexdump(True)
        decryptor = Cipher(
            algorithms.AES(zero_byte * 16),
            modes.CBC(x55 * 16),
            backend=default_backend(),
        ).decryptor()
        p.set_inbound_cipher(decryptor, 16, sha1, 12, x1f * 20)
        wsock.send(
            b"\x43\x91\x97\xbd\x5b\x50\xac\x25\x87\xc2\xc4\x6b\xc7\xe9\x38\xc0\x90\xd2\x16\x56\x0d\x71\x73\x61\x38\x7c\x4c\x3d\xfb\x97\x7d\xe2\x6e\x03\xb1\xa0\xc2\x1c\xd6\x41\x41\x4c\xb4\x59"  # noqa
        )
        cmd, m = p.read_message()
        self.assertEqual(100, cmd)
        self.assertEqual(100, m.get_int())
        self.assertEqual(1, m.get_int())
        self.assertEqual(900, m.get_int())

    def test_closed(self):
        if sys.platform.startswith("win"):  # no SIGALRM on windows
            return
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)
        p = Packetizer(wsock)
        p.set_log(util.get_logger("paramiko.transport"))
        p.set_hexdump(True)
        encryptor = Cipher(
            algorithms.AES(zero_byte * 16),
            modes.CBC(x55 * 16),
            backend=default_backend(),
        ).encryptor()
        p.set_outbound_cipher(encryptor, 16, sha1, 12, x1f * 20)

        # message has to be at least 16 bytes long, so we'll have at least one
        # block of data encrypted that contains zero random padding bytes
        m = Message('')
        m.add_byte(byte_chr(100))
        m.add_int(100)
        m.add_int(1)
        m.add_int(900)
        wsock.send = lambda x: 0
        from functools import wraps
        import errno
        import os
        import signal

        class TimeoutError(Exception):
            def __init__(self, error_message):
                if hasattr(errno, "ETIME"):
                    self.message = os.sterror(errno.ETIME)
                else:
                    self.messaage = error_message

        def timeout(seconds=1, error_message="Timer expired"):
            def decorator(func):
                def _handle_timeout(signum, frame):
                    raise TimeoutError(error_message)

                def wrapper(*args, **kwargs):
                    signal.signal(signal.SIGALRM, _handle_timeout)
                    signal.alarm(seconds)
                    try:
                        result = func(*args, **kwargs)
                    finally:
                        signal.alarm(0)
                    return result

                return wraps(func)(wrapper)

            return decorator

        send = timeout()(p.send_message)
        self.assertRaises(EOFError, send, m)

    def _linked_packetizers(self):
        """A writer and a reader sharing one AES-CBC/SHA1 keystream."""
        rsock = LoopSocket()
        wsock = LoopSocket()
        rsock.link(wsock)

        writer = Packetizer(wsock)
        writer.set_log(util.get_logger("paramiko.transport"))
        encryptor = Cipher(
            algorithms.AES(zero_byte * 16),
            modes.CBC(x55 * 16),
            backend=default_backend(),
        ).encryptor()
        writer.set_outbound_cipher(encryptor, 16, sha1, 12, x1f * 20)

        reader = Packetizer(rsock)
        reader.set_log(util.get_logger("paramiko.transport"))
        decryptor = Cipher(
            algorithms.AES(zero_byte * 16),
            modes.CBC(x55 * 16),
            backend=default_backend(),
        ).decryptor()
        reader.set_inbound_cipher(decryptor, 16, sha1, 12, x1f * 20)

        return writer, reader, wsock

    def test_send_messages_writes_once(self):
        writer, reader, wsock = self._linked_packetizers()
        writes = []
        real_send = wsock.send

        def counting_send(data):
            writes.append(len(data))
            return real_send(data)

        wsock.send = counting_send

        messages = []
        for n in range(8):
            m = Message('')
            m.add_byte(byte_chr(100))
            m.add_int(n)
            messages.append(m)
        writer.send_messages(messages)

        self.assertEqual(1, len(writes))

        # ...and the peer still decrypts every one of them, in order: the
        # cipher and MAC run across the batch the same way they would have
        # across eight separate sends.
        for n in range(8):
            cmd, m = reader.read_message()
            self.assertEqual(100, cmd)
            self.assertEqual(n, m.get_int())

    def test_send_messages_skips_empty_messages(self):
        writer, reader, wsock = self._linked_packetizers()
        full = Message('')
        full.add_byte(byte_chr(100))
        full.add_int(7)
        writer.send_messages([Message(''), full, Message('')])

        cmd, m = reader.read_message()
        self.assertEqual(100, cmd)
        self.assertEqual(7, m.get_int())

    def test_send_messages_with_nothing_to_send_writes_nothing(self):
        writer, reader, wsock = self._linked_packetizers()
        writes = []
        wsock.send = lambda data: writes.append(data) or len(data)
        writer.send_messages([])
        writer.send_messages([Message('')])
        self.assertEqual([], writes)
