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

from clicker.common.exceptions import HandsakeError, MalformedPacket
from clicker.common.globals import CLIENT_ENC_NONCE, CLIENT_MAC_NONCE, SERVER_ENC_NONCE, SERVER_MAC_NONCE
from clicker.common.util import ConnectionProtocolState, MessageHandler, Wallet, now, trail_off


class ClientHandler:
    cl_enc: AEADDecryptionContext
    sr_enc: AEADEncryptionContext
    cl_mac: AEADDecryptionContext
    sr_mac: AEADEncryptionContext

    protocol: bytes

    def __init__(self, addr: tuple[str, int], transport: asyncio.DatagramTransport, wallet: Wallet, data: bytes,
                 message_handlers: Iterable[MessageHandler]):
        self.last_seen = now()
        self.addr = addr
        self.transport = transport
        self.message_handlers = set(message_handlers)

        self.logger = logging.getLogger(f"{addr[0]}:{addr[1]}")

        if len(data) != 40:
            self.logger.error("Invalid handshake packet")
            raise MalformedPacket("Invalid handshake packet")

        wallet.esks = X25519PrivateKey.generate()
        wallet.epks = wallet.esks.public_key()
        wallet.ns = urandom(8)
        wallet.epkc = X25519PublicKey.from_public_bytes(data[:32])
        wallet.nc = data[32:]
        self.wallet = wallet

        self.client_message_id = 0
        self.server_message_id = 0
        self.client_packet_id = 0
        self.server_packet_id = 0

        self.mtu_estimate = 1500

        self.state = ConnectionProtocolState.HANDSHAKE
        self.transport.sendto((wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) + wallet.ns), self.addr)
        self.logger.info("Sent keys")

    @property
    def is_alive(self):
        return self.state not in (
            ConnectionProtocolState.ERROR, ConnectionProtocolState.DISCONNECTED
        ) and now() - self.last_seen < 5

    def handle(self, data: bytes):
        self.last_seen = now()

        match self.state:
            case ConnectionProtocolState.HANDSHAKE:
                self.__handshake(data)
            case ConnectionProtocolState.CONNECTED:
                self.__connected(data)
            case ConnectionProtocolState.DISCONNECTED:
                self.__disconnected(data)
            case ConnectionProtocolState.ERROR:
                self.__error(data)
            case ConnectionProtocolState.INITIAL:
                self.__initial(data)

    def __handshake(self, data) -> None:
        if len(data) < 40:
            self.logger.error("Invalid handshake packet")
            self.state = ConnectionProtocolState.ERROR
            raise MalformedPacket("Invalid handshake packet")
        wallet = self.wallet
        self.logger.info("\n".join([
            f"epkc: {wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}",
            f"epks: {wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}",
            f"nc: {wallet.nc.hex()}",
            f"ns: {wallet.ns.hex()}"
        ]))
        wallet.token = blake3(wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.nc + wallet.ns).digest()
        client_token = data[8:40]

        self.logger.debug(f"token: {client_token.hex()}")

        if client_token != wallet.token:
            self.logger.debug(f"ours : {self.wallet.token.hex()}")
            self.logger.error("token mismatch!")
            raise HandsakeError("Token mismatch")

        self.logger.debug("token: OK")

        self.__key_exchange()

        message = self.__verify_and_decrypt(data)
        if message is None:
            self.state = ConnectionProtocolState.ERROR
            raise HandsakeError("Invalid handshake packet (missing protocol)")

        self.state = ConnectionProtocolState.CONNECTED
        self.protocol = message
        self.logger.info("Handshake complete")
        self.logger.debug(f"protocol: {message.decode('utf-8')}")

    def __key_exchange(self):
        wallet = self.wallet
        eces = wallet.esks.exchange(wallet.epkc)
        ecps = wallet.psks.exchange(wallet.epkc)
        wallet.shared_secret = blake3(
            eces + ecps + wallet.nc + wallet.ns +
            wallet.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw)).digest()
        self.logger.debug(f"shared_secret: {wallet.shared_secret.hex()}")
        # noinspection DuplicatedCode
        self.cl_enc = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + CLIENT_ENC_NONCE), None).decryptor()
        self.sr_enc = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + SERVER_ENC_NONCE), None).encryptor()
        self.cl_mac = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + CLIENT_MAC_NONCE), None).decryptor()
        self.sr_mac = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + SERVER_MAC_NONCE), None).encryptor()

    def __verify_and_decrypt(self, data: bytes) -> bytes | None:
        try:
            p_id = int.from_bytes(data[:8], "little")
            key = self.cl_mac.update(b"\x00" * 32)
            payload = data[8:-16]
            tag = data[-16:]
            poly1305.Poly1305.verify_tag(key, data[:8] + payload, tag)
        except InvalidSignature:
            self.logger.error("Invalid signature")
            return None

        # special case for first packet
        if p_id == 0:
            payload = payload[32:]
            self.logger.debug(f"--- {trail_off(payload.hex())}")

        message_bytes = self.cl_enc.update(payload)
        message_length = int.from_bytes(message_bytes[:4], "little")
        message = message_bytes[4:message_length + 4]
        self.logger.info(f"Received message {p_id} ({message_length} bytes)")
        self.client_packet_id = p_id
        return message

    def __connected(self, data):
        message = self.__verify_and_decrypt(data)
        self.logger.info(f">>> {trail_off(message.decode('utf-8')) if message else None}")

        if message:
            asyncio.gather(*[handler(self.client_message_id, message) for handler in self.message_handlers])

    async def send(self, data: bytes):
        if self.state not in (ConnectionProtocolState.CONNECTED, ConnectionProtocolState.HANDSHAKE):
            return
        self.logger.info(f"<<< {trail_off(data.decode('utf-8'))}")
        packets = self.__encrypt_and_tag(data)
        self.logger.info(f"Sending {len(data)} bytes in {len(packets)} packets")
        for packet in packets:
            self.transport.sendto(packet, self.addr)

    def __encrypt_and_tag(self, data: bytes) -> list[bytes]:
        message_bytes = len(data).to_bytes(4, "little") + data
        packet_length = self.mtu_estimate - 24
        padded_message_bytes = message_bytes + b"\x00" * (
                packet_length - ((len(message_bytes)) % packet_length))

        ciphertext = self.sr_enc.update(padded_message_bytes)
        self.logger.debug(f"--- {trail_off(ciphertext.hex())}")

        payloads = self.__split_message(ciphertext)

        packets = []
        for payload in payloads:
            key = self.sr_mac.update(b"\x00" * 32)
            p_id = self.client_packet_id.to_bytes(8, "little")
            frame = p_id + payload
            tag = poly1305.Poly1305.generate_tag(key, frame)
            packets.append(frame + tag)
            self.client_packet_id += 1
        return packets

    def __split_message(self, data: bytes) -> list[bytes]:
        packet_length = self.mtu_estimate - 24
        return [data[i:i + packet_length] for i in range(0, len(data), packet_length)]


class OnePortProtocol(asyncio.DatagramProtocol):
    transport: asyncio.DatagramTransport

    def __init__(self, wallet: Wallet, message_handlers: Iterable[MessageHandler]):
        super().__init__()
        self.wallet = wallet
        self.message_handlers = message_handlers

        self.__clients: dict[tuple[str, int], ClientHandler] = dict()
        self.logger = logging.getLogger(f"OnePort")

        self.tasks: set[asyncio.Task] = set()
        self.closed = asyncio.Event()

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        self.logger.info(f"Listening on port {transport.get_extra_info('sockname')[1]}")

    def error_received(self, exc):
        self.logger.exception(exc)

    def datagram_received(self, data, addr):
        if addr not in self.__clients:
            try:
                c = ClientHandler(addr, self.transport, self.wallet, data, self.message_handlers)
            except (HandsakeError, MalformedPacket):
                self.logger.error(f"Handshake failed with {addr}")
                return
            self.__clients[addr] = c
            self.logger.info(f"New client {addr}")
            return

        handler = self.__clients[addr]

        try:
            handler.handle(data)
        except HandsakeError:
            self.logger.error(f"Handshake failed with {addr}")
            del self.__clients[addr]
            self.close()
        except MalformedPacket:
            self.logger.error(f"Malformed packet from {addr}")
            del self.__clients[addr]

    async def send(self, data: bytes, addr: tuple[str, int]):
        if addr not in self.__clients:
            self.logger.error(f"Attempted to send to {addr} but they are not connected")
            return
        await self.__clients[addr].send(data)

    def add_message_handler(self, handler: MessageHandler, addr: tuple[str, int]):
        self.__clients[addr].message_handlers.add(handler)

    def clean(self):
        for addr in list(self.__clients.keys()):
            if not self.__clients[addr].is_alive:
                del self.__clients[addr]

    def close(self):
        self.transport.close()

    def connection_lost(self, exc):
        self.logger.info("Connection closed")
        self.closed.set()
