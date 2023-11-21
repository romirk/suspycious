import asyncio
import collections
import logging
from os import urandom
from typing import Iterable

from blake3 import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import AEADDecryptionContext, AEADEncryptionContext, Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.common.exceptions import HandsakeError, MalformedPacket
from sus.common.globals import CLIENT_ENC_NONCE, CLIENT_MAC_NONCE, SERVER_ENC_NONCE, SERVER_MAC_NONCE
from sus.common.util import ConnectionID, ConnectionState, MessageHandler, Wallet, now, trail_off


class ClientHandler:
    """
    This class is responsible for handling clients.
    One instance of this class is created for each client.
    """
    __cl_enc: AEADDecryptionContext
    __sr_enc: AEADEncryptionContext
    __cl_mac: AEADDecryptionContext
    __sr_mac: AEADEncryptionContext

    __protocol: bytes
    __connection_id: ConnectionID

    def __init__(self, addr: tuple[str, int], transport: asyncio.DatagramTransport, wallet: Wallet,
                 message_handlers: Iterable[MessageHandler], max_packets: int = 8):
        self.__last_seen = now()
        self.__addr = addr
        self.__transport = transport
        self.__message_handlers = set(message_handlers)
        self.__state = ConnectionState.INITIAL

        self.__logger = logging.getLogger(f"{addr[0]}:{addr[1]}")

        self.__logger.info(f"New client {addr}")

        wallet.esks = X25519PrivateKey.generate()
        wallet.epks = wallet.esks.public_key()
        wallet.ns = urandom(8)

        self.__wallet = wallet

        self.__client_message_id = 0
        self.__server_message_id = 0
        self.__incoming_packet_id = 0
        self.__outgoing_packet_id = 0

        self.__mtu_estimate = 1500

        self.__incoming_buffer: collections.deque[bytes] = collections.deque(maxlen=max_packets)
        self.__incoming_keys: collections.deque[bytes] = collections.deque(maxlen=max_packets)
        self.__pending_message_length = 0
        self.__pending_message_buffer = bytearray()

    @property
    def is_alive(self):
        """
        True if the client is not in an error state and has been seen in the last 5 seconds.
        """
        return self.__state not in (
            ConnectionState.ERROR, ConnectionState.DISCONNECTED
        ) and now() - self.__last_seen < 5

    @property
    def addr(self):
        """Client address."""
        return self.__addr

    @property
    def last_seen(self):
        """Last time the client was seen, in seconds since the epoch."""
        return self.__last_seen

    @property
    def protocol(self):
        return self.__protocol

    @property
    def max_packets(self):
        return self.__incoming_buffer.maxlen

    @property
    def connection_id(self):
        return self.__connection_id

    def __gen_connection_id(self, channel_id: int = 0) -> ConnectionID:
        wallet = self.__wallet

        # figure out a way to determinisitically generate connection_id
        # for now, this just hashes the shared secret with the channel ID
        return int.from_bytes(
            blake3(
                wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                int.to_bytes(channel_id)
            ).digest()[:8], "little", signed=False)

    def __key_exchange(self):
        wallet = self.__wallet
        eces = wallet.esks.exchange(wallet.epkc)
        ecps = wallet.psks.exchange(wallet.epkc)
        wallet.shared_secret = blake3(
            eces + ecps + wallet.nc + wallet.ns +
            wallet.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw)).digest()
        self.__logger.debug(f"shared_secret: {wallet.shared_secret.hex()}")
        # noinspection DuplicatedCode
        self.__cl_enc = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + CLIENT_ENC_NONCE), None).decryptor()
        self.__sr_enc = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + SERVER_ENC_NONCE), None).encryptor()
        self.__cl_mac = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + CLIENT_MAC_NONCE), None).decryptor()
        self.__sr_mac = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + SERVER_MAC_NONCE), None).encryptor()

        for i in range(self.max_packets):
            self.__incoming_keys.append(self.__cl_mac.update(b"\x00" * 32))

    def __reform_messages(self, data: bytes) -> [bytes]:
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

    def __verify_and_decrypt(self, data: bytes) -> bytes | None:
        try:
            p_id = int.from_bytes(data[:8], "little")
            if p_id > self.__incoming_packet_id + self.max_packets or p_id < self.__incoming_packet_id:
                self.__logger.error("Packet {p_id} is too far ahead")
                return None
            key = self.__incoming_keys[p_id - self.__incoming_packet_id]
            payload = data[8:-16]
            tag = data[-16:]
            poly1305.Poly1305.verify_tag(key, data[:8] + payload, tag)
        except InvalidSignature:
            self.__logger.error("Invalid signature")
            return None

        match p_id:
            case 0:
                # special case for first packet
                payload = payload[32:]
                self.__logger.debug(f"--- {trail_off(payload.hex())}")
                self.__incoming_packet_id = 1
                message_bytes = self.__cl_enc.update(payload)

                self.__incoming_keys.popleft()
                self.__incoming_keys.append(self.__cl_mac.update(b"\x00" * 32))
                return message_bytes
            case self.__incoming_packet_id:
                self.__logger.debug(f"--- {trail_off(payload.hex())}")

                # packet has already been verified
                _ = self.__incoming_keys.popleft()
                self.__incoming_keys.append(self.__cl_mac.update(b"\x00" * 32))
                self.__incoming_packet_id += 1
                message_bytes = self.__cl_enc.update(payload)
                buffer = bytearray(message_bytes)

                while self.__incoming_buffer and self.__incoming_buffer[0] is not None:
                    packet = self.__incoming_buffer.popleft()
                    _ = self.__incoming_keys.popleft()
                    assert int.from_bytes(packet[:8], "little") == self.__incoming_packet_id
                    self.__incoming_packet_id += 1
                    payload = packet[8:-16]
                    message_bytes = self.__cl_enc.update(payload)
                    buffer.extend(message_bytes)

                return bytes(buffer)

            case _:
                self.__incoming_keys.insert(p_id - self.__incoming_packet_id, self.__cl_mac.update(payload))
                self.__incoming_buffer.insert(p_id - self.__incoming_packet_id, data)
                return None

    def __encrypt_and_tag(self, data: bytes) -> list[bytes]:
        message_bytes = len(data).to_bytes(4, "little") + data
        packet_length = self.__mtu_estimate - 24
        padded_message_bytes = message_bytes  # + b"\x00" * (
        # packet_length - ((len(message_bytes)) % packet_length))

        ciphertext = self.__sr_enc.update(padded_message_bytes)
        self.__logger.debug(f"--- {trail_off(ciphertext.hex())}")

        payloads = self.__split_message(ciphertext)

        packets = []
        for payload in payloads:
            key = self.__sr_mac.update(b"\x00" * 32)
            p_id = self.__incoming_packet_id.to_bytes(8, "little")
            frame = p_id + payload
            tag = poly1305.Poly1305.generate_tag(key, frame)
            packets.append(frame + tag)
            self.__incoming_packet_id += 1
        return packets

    def __split_message(self, data: bytes) -> list[bytes]:
        packet_length = self.__mtu_estimate - 24
        return [data[i:i + packet_length] for i in range(0, len(data), packet_length)]

    def __initial(self, data):
        if len(data) != 40:
            self.__logger.error("Invalid handshake packet")
            raise MalformedPacket("Invalid handshake packet")
        wallet = self.__wallet
        wallet.epkc = X25519PublicKey.from_public_bytes(data[:32])
        wallet.nc = data[32:]

        self.__connection_id = self.__gen_connection_id()
        self.__state = ConnectionState.HANDSHAKE
        self.__transport.sendto((wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) + wallet.ns), self.__addr)
        self.__logger.info(f"connection ID: {self.__connection_id}")

    def __handshake(self, data) -> None:
        if len(data) < 40:
            self.__logger.error("Invalid handshake packet")
            self.__state = ConnectionState.ERROR
            raise MalformedPacket("Invalid handshake packet")

        wallet = self.__wallet

        wallet.token = blake3(wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.nc + wallet.ns).digest()
        client_token = data[8:40]

        self.__logger.debug(f"token: {client_token.hex()}")

        if client_token != wallet.token:
            self.__logger.debug(f"ours : {self.__wallet.token.hex()}")
            self.__logger.error("token mismatch!")
            raise HandsakeError("Token mismatch")

        self.__logger.debug("token: OK")

        self.__key_exchange()

        buffer = self.__verify_and_decrypt(data)
        if buffer is None:
            self.__state = ConnectionState.ERROR
            raise HandsakeError("Invalid handshake packet (missing protocol)")

        messages = self.__reform_messages(buffer)
        self.__logger.debug(f"messages: {messages}")

        if not messages:
            self.__state = ConnectionState.ERROR
            raise HandsakeError("Invalid handshake packet (protocol)")
        self.__state = ConnectionState.CONNECTED
        self.__protocol = messages[0]
        self.__logger.info("Handshake complete")
        self.__logger.debug(f"protocol: {self.__protocol.decode('utf-8')}")

    def __connected(self, data):

        buffer = self.__verify_and_decrypt(data)

        if buffer is not None:
            messages = self.__reform_messages(buffer)
            # self.__logger.debug(f"messages: {messages}")
            # send to all handlers
            for msg in messages:
                asyncio.gather(*(handler(self.__addr, 0, msg) for handler in self.__message_handlers))
                self.__logger.info(f">>> {trail_off(msg.decode('utf-8'))}")

    def __disconnected(self, data):
        raise NotImplementedError

    def __error(self, data):
        raise NotImplementedError

    def change_max_packets(self, max_size: int):
        self.__incoming_buffer = collections.deque(self.__incoming_buffer, maxlen=max_size)
        self.__incoming_keys = collections.deque(self.__incoming_keys, maxlen=max_size)

    def handle(self, data: bytes):
        """
        Handles incoming packets.
        :param data: packet data
        """
        self.__last_seen = now()

        match self.__state:
            case ConnectionState.INITIAL:
                self.__initial(data)
            case ConnectionState.HANDSHAKE:
                self.__handshake(data)
            case ConnectionState.CONNECTED:
                self.__connected(data)
            case ConnectionState.DISCONNECTED:
                self.__disconnected(data)
            case ConnectionState.ERROR:
                self.__error(data)

    async def send(self, data: bytes):
        """
        Sends a message to the client.
        :param data: data to send
        """
        if self.__state not in (ConnectionState.CONNECTED, ConnectionState.HANDSHAKE):
            return
        self.__logger.info(f"<<< {trail_off(data.decode('utf-8'))}")
        packets = self.__encrypt_and_tag(data)
        self.__logger.info(f"Sending {len(data)} bytes in {len(packets)} packets")
        for packet in packets:
            self.__transport.sendto(packet, self.__addr)

    def add_message_handler(self, handler: MessageHandler):
        """
        Adds a message handler. This handler will be called when a message is received.
        :param handler: Awaitable handler function
        """
        self.__message_handlers.add(handler)
