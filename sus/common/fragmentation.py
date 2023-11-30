"""
Payload Fragmentation
=====================

To achieve a degree of asynchronicity, multiple messages can be sent concurrently.
This is achieved by splitting messages into fragments, grouping them into packets,
and sending them asynchronously.

## Payload structure

A payload is structured as follows:

```backusnaur
payload             ::= fragment*
fragment            ::= [message_id] fragment_data
fragment_data       ::= fragment_length fragment_content
fragment_length     ::= 2 bytes
fragment_content    ::= fragment_length bytes
message_id          ::= 8 bytes
```

If a `message_id` is present, it declares a new message. If it is not present, it
is a continuation of the previous message. The `message_id` is used to reassemble
the fragments into messages.

"""
from os import urandom
from time import sleep

import numpy as np

from util import now, varint, varint_decode

MESSAGE_ID_SIZE = 0
LENGTH_SIZE = 2
MIN_FRAGMENT_SIZE = MESSAGE_ID_SIZE + LENGTH_SIZE + 1


class Fragment:
    def __init__(self, message_id: int, data: bytearray):
        self.message_id = message_id
        self.data = data
        self.send_time = now()
        self.original_length = len(data)

    @property
    def complete(self):
        return len(self.data) == 0

    @property
    def is_new(self):
        return len(self.data) == self.original_length

    @property
    def priority(self):
        return np.log(self.original_length * now() / self.send_time)

    def extract(self, size: int) -> bytes:
        r = self.data[:size]
        self.data = self.data[size:]
        return bytes(r)


class Fragmenter:
    """
    This class is responsible for fragmenting and reassembling payloads.
    """

    def __init__(self, mtu_estimate: int):
        if mtu_estimate < MIN_FRAGMENT_SIZE + 24:
            raise ValueError(f"MTU estimate must be at least {MIN_FRAGMENT_SIZE}")
        self.__mtu_estimate = mtu_estimate
        self.__message_counter = 0
        self.__message_buffer: list[Fragment] = []

    def add_message(self, message: bytes):
        """
        This function is responsible for adding a message to the buffer.
        :param message: message to add
        """
        self.__message_buffer.append(Fragment(self.__message_counter, bytearray(message)))
        self.__message_counter += 1

    def __iter__(self):
        for f in self.__message_buffer:
            print(f.message_id, f.original_length, f.data[:10])
        return self

    def __next__(self):
        if not self.__message_buffer:
            raise StopIteration
        return self.__fragment()

    def __fragment(self) -> bytes:
        """
        This function is responsible for fragmenting a message.
        :return: packet containing the fragments
        """
        packet_length = self.__mtu_estimate - 24

        # fragments are sent in order of message ID
        # the size of the fragments is proportional to the priority of the message
        frozen = []
        total = 0
        i = 0
        while i < len(self.__message_buffer):
            frag = self.__message_buffer[i]
            if frag.complete:
                del self.__message_buffer[i]
                continue
            frozen.append((frag, p := frag.priority))
            total += p
            i += 1
        if not frozen:
            raise StopIteration

        data = bytearray()
        for frag, priority in frozen:
            size = min(int(packet_length * (priority / total)), len(frag.data))
            size_bytes = varint(size)
            if size + len(size_bytes) > packet_length:
                size -= len(size_bytes)
                size_bytes = varint(size)
            data.extend(size_bytes + frag.extract(size))

        if not data:
            if self.__message_buffer:
                raise RuntimeError("fragment size too small")
            raise StopIteration
        return data


class Defragmenter:
    def __init__(self):
        self.__message_buffer: list[bytearray] = []
        self.__message_length: list[int] = []
        self.__incoming: list[bytearray] = []

    @property
    def has_messages(self):
        return bool(self.__message_buffer)

    @property
    def incoming(self):
        return self.__incoming

    def __iter__(self):
        return self.__incoming.__iter__()

    def extend(self, data: bytes, idx: int):
        if idx == len(self.__message_buffer):
            self.__message_buffer.append(bytearray())
            self.__message_length.append(0)

        buffer = self.__message_buffer[idx]
        buffer.extend(data)

        if self.__message_length[idx] == 0:
            if len(buffer) < 4:
                return
            self.__message_length[idx] = int.from_bytes(buffer[:4], "little")
            self.__message_buffer[idx] = buffer[4:]

        if len(self.__message_buffer[idx]) >= self.__message_length[idx]:
            self.__incoming.append(self.__message_buffer[idx])
            del self.__message_buffer[idx]

    def update(self, data: bytes):
        """
        This function is responsible for defragmenting a packet.
        :param data: packet data
        :return: list of messages
        """
        idx = 0
        while data:
            frag_len, size_len = varint_decode(data)
            data = data[size_len:]
            if len(data) < frag_len:
                raise ValueError("invalid packet")
            self.extend(data[:frag_len], idx)
            idx += 1
            data = data[frag_len:]


if __name__ == "__main__":
    fragger = Fragmenter(150)
    defragger = Defragmenter()

    A = b"A" * 500
    B = b"B" * 300
    C = b"C" * 400

    fragger.add_message(len(A).to_bytes(4, "little") + A)
    fragger.add_message(len(B).to_bytes(4, "little") + B)
    sleep(1)
    fragger.add_message(len(C).to_bytes(4, "little") + C)

    for i, frag in enumerate(fragger):
        print(i, frag)
        defragger.update(frag)
        if not i % 5:
            R = urandom(200)
            fragger.add_message(len(R).to_bytes(4, "little") + R)

    for i, msg in enumerate(defragger):
        print(i, msg)
