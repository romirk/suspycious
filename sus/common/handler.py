import asyncio
import collections
import logging
from abc import ABC, abstractmethod
from typing import Iterable, Optional

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import poly1305
from cryptography.hazmat.primitives.ciphers import AEADDecryptionContext, AEADEncryptionContext, Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.common.exceptions import MalformedPacket
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

    # internal objects
    _transport: asyncio.DatagramTransport
    _logger: logging.Logger

    _state: ConnectionState
    "Connection state"

    # cryptography
    _wallet: Wallet
    "Cryptographic wallet"
    _inc_dec: AEADDecryptionContext
    "Incoming decryption context"
    _out_enc: AEADEncryptionContext
    "Outgoing encryption context"
    _inc_mac: AEADDecryptionContext
    "Incoming MAC context"
    _out_mac: AEADEncryptionContext
    "Outgoing MAC context"

    # metadata
    _addr: Address
    "Endpoint address"
    _app_id: bytes
    "Application ID"
    _con_id: ConnectionID
    "Connection ID"
    _last_seen: float
    "Last time the client was seen"
    _mtu_estimate: int
    "Estimated MTU"

    # message reconstruction
    _pending_message_buffer: bytes
    _pending_message_length: int

    # message ordering
    _incoming_packets: collections.deque[bytes]
    _incoming_keys: collections.deque[bytes]
    _outgoing_buffer: bytearray
    _incoming_packet_id: int
    _outgoing_packet_id: int

    # message handlers
    _message_callbacks: set[MessageCallback]
    _send_loop_task: asyncio.Task

    def __init__(self, addr: Address, transport: asyncio.DatagramTransport, app_id: bytes, wallet: Wallet,
                 message_handlers: Iterable[MessageCallback], max_packets: int = 100):
        self._logger = logging.getLogger(f"{addr[0]}:{addr[1]}")
        self._addr = addr
        self._transport = transport
        self._app_id = app_id
        self._wallet = wallet

        self._last_seen = now()
        self._message_callbacks = set(message_handlers or [])
        self._state = ConnectionState.INITIAL
        self._mtu_estimate = 1500

        self._con_id = 0

        self._incoming_packet_id = 0
        self._incoming_packets: collections.deque[bytes] = collections.deque([b""] * max_packets, maxlen=max_packets)
        self._incoming_keys: collections.deque[bytes] = collections.deque([b""] * max_packets, maxlen=max_packets)
        self._pending_message_length = 0
        self._pending_message_buffer = bytearray()

        self._outgoing_packet_id = 0
        self._outgoing_buffer = bytearray()

        self._send_loop_task: asyncio.Task = asyncio.create_task(self._send_loop())

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
        ) and now() - self._last_seen < 5

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
        return self._last_seen

    @property
    def protocol(self):
        return self._app_id

    @property
    def max_packets(self):
        return self._incoming_packets.maxlen

    @property
    def connection_id(self):
        return self._con_id

    # task methods
    async def _send_loop(self):
        try:
            while self._state not in (ConnectionState.ERROR, ConnectionState.DISCONNECTED):
                await asyncio.sleep(1)
                self._flush()
        except asyncio.CancelledError:
            return

    # utility methods

    def _gen_secrets(self, ecps: bytes, eces: bytes):
        """
        Generate shared secrets and encryption contexts.
        :param ecps:
        :param eces:
        :return:
        """
        wallet = self._wallet
        wallet.shared_secret = blake3(
            eces + ecps + wallet.nc + wallet.ns +
            wallet.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw)).digest()

        # swap nonces if we are the server
        nonces = (_CLIENT_NONCES, _SERVER_NONCES) if self._wallet.psks is None else (_SERVER_NONCES, _CLIENT_NONCES)

        # create encryption and mac contexts
        self._inc_dec = Cipher(ChaCha20(wallet.shared_secret, nonces[0][0]), None).decryptor()
        self._out_enc = Cipher(ChaCha20(wallet.shared_secret, nonces[1][0]), None).encryptor()
        self._inc_mac = Cipher(ChaCha20(wallet.shared_secret, nonces[0][1]), None).decryptor()
        self._out_mac = Cipher(ChaCha20(wallet.shared_secret, nonces[1][1]), None).encryptor()

        for _ in range(self.max_packets):
            self._incoming_keys.append(self._inc_mac.update(b"\x00" * 32))

    def _reform_messages(self, data: bytes) -> list[bytes]:
        """
        Reform messages from a buffer.

        :param data: buffer
        :return: list of messages
        """
        buffer = self._pending_message_buffer + data
        pending_length = self._pending_message_length
        messages = []
        # self._logger.debug(f"buffer: {buffer.hex()}")
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
        self._pending_message_buffer = buffer
        self._pending_message_length = pending_length
        # self._logger.debug(f"pending: {pending_length}")
        return messages

    def _split_message(self, data: bytes) -> list[bytes]:
        packet_length = self._mtu_estimate - 24
        return [data[i:i + packet_length] for i in range(0, len(data), packet_length)]

    def _verify_and_decrypt(self, data: bytes) -> bytes | None:
        if len(data) < 28:
            raise MalformedPacket("Packet too short")

        p_id = int.from_bytes(data[4:12], "little")
        if p_id > self._incoming_packet_id + self.max_packets or p_id < self._incoming_packet_id:
            self._logger.error(f"Packet {p_id} dropped")
            self._logger.debug(f"Current packet ID: {self._incoming_packet_id}")
            return None
        key = self._incoming_keys[p_id - self._incoming_packet_id]
        payload = data[12:-16]
        tag = data[-16:]

        try:
            poly1305.Poly1305.verify_tag(key, data[:-16], tag)
        except InvalidSignature:
            self._logger.error("Invalid signature\n\texpected: %s\n\tgot: %s", tag.hex(), key.hex())
            return None

        if not p_id and self._wallet.psks is not None:
            # we are the server and this is the first packet from the client
            # we need to exclude the token (first 32 bytes) from the decryption
            # process
            payload = payload[32:]

        if p_id == self._incoming_packet_id:
            self._logger.debug(f"--- {trail_off(payload.hex())}")

            # packet has already been verified
            self._incoming_keys.popleft()
            self._incoming_keys.append(self._inc_mac.update(b"\x00" * 32))
            self._incoming_packet_id += 1
            message_bytes = self._inc_dec.update(payload)
            buffer = bytearray(message_bytes)

            while self._incoming_packets[0]:
                packet = self._incoming_packets.popleft()
                _ = self._incoming_keys.popleft()

                p_id = int.from_bytes(packet[4:12], "little")
                self._logger.debug(f"expected pid: {self._incoming_packet_id} got {p_id}")
                assert p_id == self._incoming_packet_id

                self._incoming_keys.append(self._inc_mac.update(b"\x00" * 32))
                self._incoming_packets.append(b"")
                self._incoming_packet_id += 1

                payload = packet[12:-16]
                message_bytes = self._inc_dec.update(payload)
                buffer.extend(message_bytes)

            return bytes(buffer)
        else:
            # not the next packet
            self._incoming_keys.insert(p_id - self._incoming_packet_id, self._inc_mac.update(payload))
            self._incoming_packets.insert(p_id - self._incoming_packet_id, data)
            return None

    def _encrypt_and_tag(self, data: bytes, token: Optional[bytes] = None) -> list[bytes]:
        message_bytes = len(data).to_bytes(4, "little") + data
        padded_message_bytes = message_bytes  # + b"\x00" * (
        # packet_length - ((len(message_bytes)) % packet_length))

        ciphertext = self._out_enc.update(padded_message_bytes)
        self._logger.debug(f"--- {trail_off(ciphertext.hex())}")

        if token:
            self._logger.debug(f"TOK {trail_off(token.hex())}")
            ciphertext = token + ciphertext

        payloads = self._split_message(ciphertext)
        con_id = self._con_id.to_bytes(4, "little")

        packets = []
        for payload in payloads:
            key = self._out_mac.update(b"\x00" * 32)
            p_id = self._outgoing_packet_id.to_bytes(8, "little")
            frame = con_id + p_id + payload
            tag = poly1305.Poly1305.generate_tag(key, frame)
            packets.append(frame + tag)
            self._outgoing_packet_id += 1
        return packets

    def _gen_connection_id(self, channel_id: int = 0) -> ConnectionID:
        wallet = self._wallet

        # TODO figure out a way to deterministically generate connection_id
        # for now, this just hashes the shared secret with the channel ID
        return int.from_bytes(
            blake3(
                wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                int.to_bytes(channel_id)
            ).digest()[:4], "little", signed=False)

    def _flush(self):
        """
        Flushes the outgoing buffer, sending all pending messages.
        Sends multiple packets if necessary. Sends an empty packet if there is no data to send.
        """
        packets = self._encrypt_and_tag(self._outgoing_buffer or b"\x00")
        self._logger.debug(f"Sending {len(self._outgoing_buffer)} bytes in {len(packets)} packets")
        for packet in packets:
            self._transport.sendto(packet, self._addr)
        self._outgoing_buffer.clear()

    def _send_later(self, data: bytes):
        """
        Schedule a message to be sent to the client.
        :param data: data to send
        """
        if self._state not in (ConnectionState.CONNECTED, ConnectionState.HANDSHAKE):
            return
        self._logger.debug(f"<<< {trail_off(data.decode('utf-8'))}")
        self._outgoing_buffer.extend(data)

    def _connected(self, data):
        """
        Handles connected packets.
        :param data: packet data
        """
        buffer = self._verify_and_decrypt(data)

        if buffer is not None:
            messages = self._reform_messages(buffer)
            # send to all handlers
            for msg in messages:
                asyncio.gather(*(handler(self.connection_id, msg) for handler in self._message_callbacks))
                self._logger.debug(f">>> {trail_off(msg.decode('utf-8'))}")

    # public methods

    def send(self, data: bytes):
        """
        Schedules a message to be sent.
        :param data: message data
        """
        self._send_later(data)

    def send_now(self, data: bytes, token: Optional[bytes] = None):
        """DO NOT USE THIS FUNCTION UNLESS YOU KNOW WHAT YOU ARE DOING"""
        self._outgoing_buffer.extend(data)
        packets = self._encrypt_and_tag(self._outgoing_buffer or b"\x00", token)
        self._logger.debug(f"Sending {len(self._outgoing_buffer)} bytes in {len(packets)} packets")
        for packet in packets:
            self._transport.sendto(packet, self._addr)
        self._outgoing_buffer.clear()

    def handle(self, data: bytes):
        """
        Handles incoming packets.
        :param data: packet data
        """
        self._last_seen = now()

        match self._state:
            case ConnectionState.INITIAL:
                self._initial(data)
            case ConnectionState.HANDSHAKE:
                self._handshake(data)
            case ConnectionState.CONNECTED:
                self._connected(data)
            case ConnectionState.DISCONNECTED:
                self._disconnected(data)
            case ConnectionState.ERROR:
                self._error(data)

    def add_message_handler(self, handler: MessageCallback):
        """
        Adds a message handler. This handler will be called when a message is received.
        :param handler: Awaitable handler function
        """
        self._message_callbacks.add(handler)

    def change_max_packets(self, max_size: int):
        """
        Change the maximum number of packets to buffer.
        :param max_size:
        :return:
        """
        self._incoming_packets = collections.deque(self._incoming_packets, maxlen=max_size)
        self._incoming_keys = collections.deque(self._incoming_keys, maxlen=max_size)

    def disconnect(self):
        """
        Disconnect.
        """
        self._state = ConnectionState.DISCONNECTED
        self._logger.info("Disconnected")
        self._send_loop_task.cancel()
