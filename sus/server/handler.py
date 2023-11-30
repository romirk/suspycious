import asyncio
import collections
import logging
from os import urandom
from typing import Callable, Iterable

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.common.exceptions import HandshakeError, MalformedPacket
from sus.common.globals import CLIENT_ENC_NONCE, CLIENT_MAC_NONCE, SERVER_ENC_NONCE, SERVER_MAC_NONCE
from sus.common.handler import BaseHandler
from sus.common.util import Address, ConnectionID, ConnectionState, MessageHandler, Wallet, now, trail_off


class ClientHandler(BaseHandler):
    """
    This class is responsible for handling clients.
    One instance of this class is created for each client.
    """

    def __init__(self, addr: Address, transport: asyncio.DatagramTransport, wallet: Wallet,
                 message_handlers: Iterable[MessageHandler], max_packets: int = 100, async_send: bool = False):
        self.__last_seen = now()
        self.__addr = addr
        self.__transport = transport
        self.__message_handlers = set(message_handlers)
        self.__state = ConnectionState.INITIAL
        self.send: Callable[[bytes], None] = self.__send_later if async_send else self.__send_now

        self.__logger = logging.getLogger(f"{addr[0]}:{addr[1]}")

        self.__logger.info(f"New client {addr}")

        wallet.esks = X25519PrivateKey.generate()
        wallet.epks = wallet.esks.public_key()
        wallet.ns = urandom(8)

        self.__wallet = wallet

        self.__mtu_estimate = 1500

        self.__incoming_packet_id = 0
        self.__incoming_packets: collections.deque[bytes] = collections.deque([b""] * max_packets, maxlen=max_packets)
        self.__incoming_keys: collections.deque[bytes] = collections.deque([b""] * max_packets, maxlen=max_packets)
        self.__pending_message_length = 0
        self.__pending_message_buffer = bytearray()

        self.__outgoing_packet_id = 0
        self.__outgoing_buffer = bytearray()

        self.__send_loop_task: asyncio.Task = asyncio.create_task(self.__send_loop())

    def __del__(self):
        self.disconnect()

    @property
    def __pid(self):
        return self.__incoming_packet_id

    @__pid.setter
    def __pid(self, value):
        self.__logger.debug(f"packet ID: {value}")
        self.__incoming_packet_id = value

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
        return self.__app_id

    @property
    def max_packets(self):
        return self.__incoming_packets.maxlen

    @property
    def connection_id(self):
        return self.__con_id

    async def __send_loop(self):
        try:
            while self.__state not in (ConnectionState.ERROR, ConnectionState.DISCONNECTED):
                await asyncio.sleep(1)
                self.__flush()
        except asyncio.CancelledError:
            return

    def __gen_connection_id(self, channel_id: int = 0) -> ConnectionID:
        wallet = self.__wallet

        # figure out a way to deterministically generate connection_id
        # for now, this just hashes the shared secret with the channel ID
        return int.from_bytes(
            blake3(
                wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                int.to_bytes(channel_id)
            ).digest()[:4], "little", signed=False)

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
        self.__inc_dec = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + CLIENT_ENC_NONCE), None).decryptor()
        self.__out_enc = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + SERVER_ENC_NONCE), None).encryptor()
        self.__inc_mac = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + CLIENT_MAC_NONCE), None).decryptor()
        self.__out_mac = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + SERVER_MAC_NONCE), None).encryptor()

        for _ in range(self.max_packets):
            self.__incoming_keys.append(self.__inc_mac.update(b"\x00" * 32))


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

        self.__con_id = self.__gen_connection_id()
        self.__state = ConnectionState.HANDSHAKE
        self.__transport.sendto((wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) + wallet.ns), self.__addr)
        self.__logger.info(f"connection ID: {self.__con_id}")

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
            raise HandshakeError("Token mismatch")

        self.__logger.debug("token: OK")

        self.__key_exchange()

        buffer = self.__verify_and_decrypt(data)
        if buffer is None:
            self.__state = ConnectionState.ERROR
            raise HandshakeError("Invalid handshake packet (missing protocol)")

        messages = self.__reform_messages(buffer)

        if not messages:
            self.__state = ConnectionState.ERROR
            raise HandshakeError("Invalid handshake packet (protocol)")
        self.__state = ConnectionState.CONNECTED
        self.__app_id = messages[0]
        self.__logger.info("Handshake complete")
        self.__logger.debug(f"protocol: {self.__app_id.decode('utf-8')}")

    def __connected(self, data):

        buffer = self.__verify_and_decrypt(data)

        if buffer is not None:
            messages = self.__reform_messages(buffer)
            # self.__logger.debug(f"messages: {messages}")
            # send to all handlers
            for msg in messages:
                asyncio.gather(*(handler(self.connection_id, msg) for handler in self.__message_handlers))
                self.__logger.debug(f">>> {trail_off(msg.decode('utf-8'))}")

    def __disconnected(self, data):
        raise NotImplementedError

    def __error(self, data):
        self.__logger.error(f"Received data in error state: {trail_off(data.hex())}")

    def change_max_packets(self, max_size: int):
        self.__incoming_packets = collections.deque(self.__incoming_packets, maxlen=max_size)
        self.__incoming_keys = collections.deque(self.__incoming_keys, maxlen=max_size)
