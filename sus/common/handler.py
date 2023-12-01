import asyncio
import collections
import logging
from abc import ABC, abstractmethod
from typing import Iterable

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import poly1305
from cryptography.hazmat.primitives.ciphers import AEADDecryptionContext, AEADEncryptionContext, Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.common.globals import CLIENT_ENC_NONCE, CLIENT_MAC_NONCE, SERVER_ENC_NONCE, SERVER_MAC_NONCE
from sus.common.util import Address, ConnectionID, ConnectionState, MessageCallback, Wallet, now, trail_off

_CLIENT_NONCES = [b"\x00" * 8 + CLIENT_ENC_NONCE, b"\x00" * 8 + CLIENT_MAC_NONCE]
_SERVER_NONCES = [b"\x00" * 8 + SERVER_ENC_NONCE, b"\x00" * 8 + SERVER_MAC_NONCE]


class BaseEndpoint(ABC):
    """
    Common endpoint class.

    This class implements the common functionality of the client and server endpoints.
    Any methods that are not implemented here are implemented in the client and server endpoint classes.
    """

    _logger: logging.Logger
    _addr: Address

    _state: ConnectionState

    __inc_dec: AEADDecryptionContext
    __out_enc: AEADEncryptionContext
    __inc_mac: AEADDecryptionContext
    __out_mac: AEADEncryptionContext

    _transport: asyncio.DatagramTransport

    _app_id: bytes
    _con_id: ConnectionID

    __last_seen: float

    __pending_message_buffer: bytes
    __pending_message_length: int

    __incoming_packets: collections.deque[bytes]
    __incoming_keys: collections.deque[bytes]

    # __outgoing_messages: collections.deque[bytes]
    __outgoing_buffer: bytearray

    _incoming_packet_id: int
    _outgoing_packet_id: int

    __mtu_estimate: int

    __message_callbacks: set[MessageCallback]
    __send_loop_task: asyncio.Task

    def __init__(self, addr: Address, transport: asyncio.DatagramTransport, app_id: bytes, wallet: Wallet,
                 message_handlers: Iterable[MessageCallback], max_packets: int = 100):
        self._logger = logging.getLogger(f"{addr[0]}:{addr[1]}")
        self._addr = addr
        self._transport = transport
        self._app_id = app_id
        self._wallet = wallet

        self.__last_seen = now()
        self.__message_callbacks = set(message_handlers or [])
        self._state = ConnectionState.INITIAL
        self.__mtu_estimate = 1500

        self._incoming_packet_id = 0
        self.__incoming_packets: collections.deque[bytes] = collections.deque([b""] * max_packets, maxlen=max_packets)
        self.__incoming_keys: collections.deque[bytes] = collections.deque([b""] * max_packets, maxlen=max_packets)
        self.__pending_message_length = 0
        self.__pending_message_buffer = bytearray()

        self._outgoing_packet_id = 0
        self.__outgoing_buffer = bytearray()

        self.__send_loop_task: asyncio.Task = asyncio.create_task(self.__send_loop())

    def __del__(self):
        self.disconnect()

    # abstract methods
    @abstractmethod
    def _initial(self, data: bytes):
        """
        Handles initial packets.
        :param data: packet data
        """
        raise NotImplementedError

    @abstractmethod
    def _handshake(self, data: bytes):
        """
        Handles handshake packets.
        :param data: packet data
        """
        raise NotImplementedError

    @abstractmethod
    def _disconnected(self, data: bytes):
        """
        Handles disconnected packets.
        :param data: packet data
        """
        raise NotImplementedError

    @abstractmethod
    def _error(self, data: bytes):
        """
        Handles error packets.
        :param data: packet data
        """
        raise NotImplementedError

    # properties
    @property
    def is_alive(self):
        """
        True if the client is not in an error state and has been seen in the last 5 seconds.
        """
        return self._state not in (
            ConnectionState.ERROR, ConnectionState.DISCONNECTED
        ) and now() - self.__last_seen < 5

    @property
    def addr(self):
        """Client address."""
        return self._addr

    @property
    def state(self):
        """Connection state."""
        return self._state

    @property
    def last_seen(self):
        """Last time the client was seen, in seconds since the epoch."""
        return self.__last_seen

    @property
    def protocol(self):
        return self._app_id

    @property
    def max_packets(self):
        return self.__incoming_packets.maxlen

    @property
    def connection_id(self):
        return self._con_id

    # task methods
    async def __send_loop(self):
        try:
            while self._state not in (ConnectionState.ERROR, ConnectionState.DISCONNECTED):
                await asyncio.sleep(1)
                self.__flush()
        except asyncio.CancelledError:
            return

    # utility methods

    def _gen_secrets(self, ecps: bytes, eces: bytes):
        wallet = self._wallet
        wallet.shared_secret = blake3(
            eces + ecps + wallet.nc + wallet.ns +
            wallet.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw)).digest()

        nonces = (_CLIENT_NONCES, _SERVER_NONCES) if self._wallet.psks is None else (_SERVER_NONCES, _CLIENT_NONCES)
        self.__inc_dec = Cipher(ChaCha20(wallet.shared_secret, nonces[0][0]), None).decryptor()
        self.__out_enc = Cipher(ChaCha20(wallet.shared_secret, nonces[1][0]), None).encryptor()
        self.__inc_mac = Cipher(ChaCha20(wallet.shared_secret, nonces[0][1]), None).decryptor()
        self.__out_mac = Cipher(ChaCha20(wallet.shared_secret, nonces[1][1]), None).encryptor()

    def __reform_messages(self, data: bytes) -> list[bytes]:
        buffer = self.__pending_message_buffer + data
        pending_length = self.__pending_message_length
        messages = []
        # self.__logger.debug(f"buffer: {buffer.hex()}")
        while len(buffer) >= pending_length:
            if pending_length == 0:
                if len(buffer) < 4:
                    break
                pending_length = int.from_bytes(buffer[:4], "little")
                buffer = buffer[4:]
            else:
                messages.append(bytes(buffer[:pending_length]))
                buffer = buffer[pending_length:]
                pending_length = 0
        self.__pending_message_buffer = buffer
        self.__pending_message_length = pending_length
        # self.__logger.debug(f"pending: {pending_length}")
        return messages

    def __split_message(self, data: bytes) -> list[bytes]:
        packet_length = self.__mtu_estimate - 24
        return [data[i:i + packet_length] for i in range(0, len(data), packet_length)]

    def __verify_and_decrypt(self, data: bytes) -> bytes | None:
        try:
            p_id = int.from_bytes(data[:8], "little")
            if p_id > self._incoming_packet_id + self.max_packets or p_id < self._incoming_packet_id:
                self._logger.error(f"Packet {p_id} dropped")
                self._logger.debug(f"Current packet ID: {self._incoming_packet_id}")
                return None
            key = self.__incoming_keys[p_id - self._incoming_packet_id]
            payload = data[8:-16]
            tag = data[-16:]
            poly1305.Poly1305.verify_tag(key, data[:8] + payload, tag)
        except InvalidSignature:
            self._logger.error("Invalid signature")
            return None

        if not p_id and self._wallet.psks is not None:
            # we are the server and this is the first packet from the client
            # we need to exclude the token (first 32 bytes) from the decryption
            # process
            payload = payload[32:]

        if p_id == self._incoming_packet_id:
            self._logger.debug(f"--- {trail_off(payload.hex())}")

            # packet has already been verified
            self.__incoming_keys.popleft()
            self.__incoming_keys.append(self.__inc_mac.update(b"\x00" * 32))
            self._incoming_packet_id += 1
            message_bytes = self.__inc_dec.update(payload)
            buffer = bytearray(message_bytes)

            while self.__incoming_packets[0]:
                packet = self.__incoming_packets.popleft()
                _ = self.__incoming_keys.popleft()
                p_id = int.from_bytes(packet[:8], "little")
                self._logger.debug(f"expected pid: {self._incoming_packet_id} got {p_id}")
                assert p_id == self._incoming_packet_id
                self.__incoming_keys.append(self.__inc_mac.update(b"\x00" * 32))
                self.__incoming_packets.append(b"")
                self._incoming_packet_id += 1
                payload = packet[8:-16]
                message_bytes = self.__inc_dec.update(payload)
                buffer.extend(message_bytes)

            return bytes(buffer)
        else:
            # not the next packet
            self.__incoming_keys.insert(p_id - self._incoming_packet_id, self.__inc_mac.update(payload))
            self.__incoming_packets.insert(p_id - self._incoming_packet_id, data)
            return None

    def __encrypt_and_tag(self, data: bytes, token: bytes = b"") -> list[bytes]:
        message_bytes = len(data).to_bytes(4, "little") + data
        padded_message_bytes = message_bytes  # + b"\x00" * (
        # packet_length - ((len(message_bytes)) % packet_length))

        ciphertext = self.__out_enc.update(padded_message_bytes)
        self._logger.debug(f"--- {trail_off(ciphertext.hex())}")

        if token:
            self._logger.debug(f"TOK {trail_off(token.hex())}")

        payloads = self.__split_message(token + ciphertext)

        packets = []
        for payload in payloads:
            key = self.__out_mac.update(b"\x00" * 32)
            p_id = self._outgoing_packet_id.to_bytes(8, "little")
            frame = p_id + payload
            tag = poly1305.Poly1305.generate_tag(key, frame)
            packets.append(frame + tag)
            self._outgoing_packet_id += 1
        return packets

    def _gen_connection_id(self, channel_id: int = 0) -> ConnectionID:
        wallet = self._wallet

        # figure out a way to deterministically generate connection_id
        # for now, this just hashes the shared secret with the channel ID
        return int.from_bytes(
            blake3(
                wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                int.to_bytes(channel_id)
            ).digest()[:4], "little", signed=False)

    def __flush(self):
        """
        Flushes the outgoing buffer, sending all pending messages.
        Sends multiple packets if necessary. Sends an empty packet if there is no data to send.
        """
        packets = self.__encrypt_and_tag(self.__outgoing_buffer or b"\x00")
        self._logger.debug(f"Sending {len(self.__outgoing_buffer)} bytes in {len(packets)} packets")
        for packet in packets:
            self._transport.sendto(packet, self._addr)
        self.__outgoing_buffer.clear()

    def __send_later(self, data: bytes):
        """
        Schedule a message to be sent to the client.
        :param data: data to send
        """
        if self._state not in (ConnectionState.CONNECTED, ConnectionState.HANDSHAKE):
            return
        self._logger.debug(f"<<< {trail_off(data.decode('utf-8'))}")
        self.__outgoing_buffer.extend(data)

    def __connected(self, data):
        """
        Handles connected packets.
        :param data: packet data
        """
        buffer = self.__verify_and_decrypt(data)

        if buffer is not None:
            messages = self.__reform_messages(buffer)
            # send to all handlers
            for msg in messages:
                asyncio.gather(*(handler(self.connection_id, msg) for handler in self.__message_callbacks))
                self._logger.debug(f">>> {trail_off(msg.decode('utf-8'))}")

    # public methods

    def send(self, data: bytes):
        """
        Schedules a message to be sent.
        :param data: message data
        """
        self.__send_later(data)

    def send_now(self, data: bytes, token: bytes = b""):
        """DO NOT USE THIS FUNCTION UNLESS YOU KNOW WHAT YOU ARE DOING"""
        self.__outgoing_buffer.extend(data)
        packets = self.__encrypt_and_tag(self.__outgoing_buffer or b"\x00", token)
        self._logger.debug(f"Sending {len(self.__outgoing_buffer)} bytes in {len(packets)} packets")
        for packet in packets:
            self._transport.sendto(packet, self._addr)
        self.__outgoing_buffer.clear()

    def handle(self, data: bytes):
        """
        Handles incoming packets.
        :param data: packet data
        """
        self.__last_seen = now()

        match self._state:
            case ConnectionState.INITIAL:
                self._initial(data)
            case ConnectionState.HANDSHAKE:
                self._handshake(data)
            case ConnectionState.CONNECTED:
                self.__connected(data)
            case ConnectionState.DISCONNECTED:
                self._disconnected(data)
            case ConnectionState.ERROR:
                self._error(data)

    def add_message_handler(self, handler: MessageCallback):
        """
        Adds a message handler. This handler will be called when a message is received.
        :param handler: Awaitable handler function
        """
        self.__message_callbacks.add(handler)

    def change_max_packets(self, max_size: int):
        """
        Change the maximum number of packets to buffer.
        :param max_size:
        :return:
        """
        self.__incoming_packets = collections.deque(self.__incoming_packets, maxlen=max_size)
        self.__incoming_keys = collections.deque(self.__incoming_keys, maxlen=max_size)

    def disconnect(self):
        """
        Disconnect.
        """
        self._state = ConnectionState.DISCONNECTED
        self._logger.info("Disconnected")
        self.__send_loop_task.cancel()
