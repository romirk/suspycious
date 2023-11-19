import asyncio
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
from sus.common.util import ConnectionState, MessageHandler, Wallet, now, trail_off


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

    def __init__(self, addr: tuple[str, int], transport: asyncio.DatagramTransport, wallet: Wallet,
                 message_handlers: Iterable[MessageHandler]):
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
        self.__client_packet_id = 0
        self.__server_packet_id = 0

        self.__mtu_estimate = 1500

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

    def __verify_and_decrypt(self, data: bytes) -> bytes | None:
        try:
            p_id = int.from_bytes(data[:8], "little")
            key = self.__cl_mac.update(b"\x00" * 32)
            payload = data[8:-16]
            tag = data[-16:]
            poly1305.Poly1305.verify_tag(key, data[:8] + payload, tag)
        except InvalidSignature:
            self.__logger.error("Invalid signature")
            return None

        # special case for first packet
        if p_id == 0:
            payload = payload[32:]
            self.__logger.debug(f"--- {trail_off(payload.hex())}")

        message_bytes = self.__cl_enc.update(payload)
        message_length = int.from_bytes(message_bytes[:4], "little")
        message = message_bytes[4:message_length + 4]
        self.__logger.info(f"Received message {p_id} ({message_length} bytes)")
        self.__client_packet_id = p_id
        return message

    def __encrypt_and_tag(self, data: bytes) -> list[bytes]:
        message_bytes = len(data).to_bytes(4, "little") + data
        packet_length = self.__mtu_estimate - 24
        padded_message_bytes = message_bytes + b"\x00" * (
                packet_length - ((len(message_bytes)) % packet_length))

        ciphertext = self.__sr_enc.update(padded_message_bytes)
        self.__logger.debug(f"--- {trail_off(ciphertext.hex())}")

        payloads = self.__split_message(ciphertext)

        packets = []
        for payload in payloads:
            key = self.__sr_mac.update(b"\x00" * 32)
            p_id = self.__client_packet_id.to_bytes(8, "little")
            frame = p_id + payload
            tag = poly1305.Poly1305.generate_tag(key, frame)
            packets.append(frame + tag)
            self.__client_packet_id += 1
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

        self.__state = ConnectionState.HANDSHAKE
        self.__transport.sendto((wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) + wallet.ns), self.__addr)

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

        message = self.__verify_and_decrypt(data)
        if message is None:
            self.__state = ConnectionState.ERROR
            raise HandsakeError("Invalid handshake packet (missing protocol)")

        self.__state = ConnectionState.CONNECTED
        self.__protocol = message
        self.__logger.info("Handshake complete")
        self.__logger.debug(f"protocol: {message.decode('utf-8')}")

    def __connected(self, data):
        message = self.__verify_and_decrypt(data)
        self.__logger.info(f">>> {trail_off(message.decode('utf-8')) if message else None}")

        if message:
            # send to all handlers
            asyncio.gather(*[
                handler(self.addr, self.__client_message_id, message)
                for handler in self.__message_handlers
            ])

    def __disconnected(self, data):
        raise NotImplementedError

    def __error(self, data):
        raise NotImplementedError

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
