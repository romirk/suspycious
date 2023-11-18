import asyncio
import logging
from typing import Any, Callable, Iterable, Optional

from cryptography.hazmat.primitives import poly1305
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20

from clicker.common.globals import CLIENT_ENC_NONCE, CLIENT_MAC_NONCE, SERVER_ENC_NONCE, SERVER_MAC_NONCE
from clicker.common.util import ConnectionProtocolState, MessageHandler, Wallet, now, trail_off


class ClickerClientProtocol(asyncio.DatagramProtocol):
    transport: asyncio.DatagramTransport

    def __init__(self, wallet: Wallet, protcol_id: bytes,
                 handlers: Optional[Iterable[MessageHandler]] = None):
        super().__init__()

        self.wallet = wallet
        self.protocol_id = protcol_id
        self.state = ConnectionProtocolState.INITIAL

        self.logger = logging.getLogger(f"clicker-cl")

        self.last_seen = now()

        self.cl_enc = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + CLIENT_ENC_NONCE), None).encryptor()
        self.sr_enc = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + SERVER_ENC_NONCE), None).decryptor()
        self.cl_mac = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + CLIENT_MAC_NONCE), None).encryptor()
        self.sr_mac = Cipher(ChaCha20(wallet.shared_secret, b"\x00" * 8 + SERVER_MAC_NONCE), None).decryptor()

        self.client_message_id = 0
        self.server_message_id = 0
        self.client_packet_id = 0
        self.server_packet_id = 0

        self.mtu_estimate = 1500

        self.message_handlers: set[MessageHandler] = set(handlers or [])
        self.handshake_event = asyncio.Event()
        self.diconnection_event = asyncio.Event()

    def add_message_handler(self, handler: MessageHandler):
        self.message_handlers.add(handler)

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        self.state = ConnectionProtocolState.HANDSHAKE
        self.send(self.protocol_id, self.wallet.token)
        self.state = ConnectionProtocolState.CONNECTED
        self.last_seen = now()
        self.logger.debug("Handshake complete")
        self.handshake_event.set()

    def datagram_received(self, data: bytes, addr: tuple[str, int]):

        match self.state:
            case ConnectionProtocolState.CONNECTED:
                pid, message = self.__verify_and_decrypt(data)
                self.logger.info(f">>> {trail_off(message.decode('utf-8')) if message else None}")
                self.handle_message(pid, message)

    def __verify_and_decrypt(self, data: bytes) -> tuple[None, None] | tuple[int, bytes]:
        try:
            key = self.sr_mac.update(b"\x00" * 32)
            p_id = data[:8]
            payload = data[8:-16]
            tag = data[-16:]
            frame = p_id + payload
            poly1305.Poly1305.verify_tag(key, frame, tag)
        except poly1305.InvalidSignature:
            self.logger.error("Invalid signature")
            return None, None

        p_id = int.from_bytes(p_id, "little")
        message_bytes = self.sr_enc.update(payload)
        message_length = int.from_bytes(message_bytes[:4], "little")
        message: bytes = message_bytes[4:message_length + 4]
        # self.logger.info(f"Received message {p_id} ({message_length} bytes)")
        self.last_seen = now()
        self.server_packet_id = p_id
        return p_id, message

    def __split_message(self, data: bytes) -> list[bytes]:
        packet_length = self.mtu_estimate - 24
        return [data[i:i + packet_length] for i in range(0, len(data), packet_length)]

    def __encrypt_and_tag(self, data: bytes, token: bytes) -> list[bytes]:
        message_bytes = len(data).to_bytes(4, "little") + data
        packet_length = self.mtu_estimate - 24
        padded_message_bytes = message_bytes + b"\x00" * (
                packet_length - ((len(message_bytes) + len(token)) % packet_length))

        ciphertext = self.cl_enc.update(padded_message_bytes)
        self.logger.debug(f"--- {trail_off(ciphertext.hex())}")
        if token:
            self.logger.debug(f"TOK {trail_off(token.hex())}")

        payloads = self.__split_message(token + ciphertext)

        packets = []
        for payload in payloads:
            key = self.cl_mac.update(b"\x00" * 32)
            p_id = self.client_packet_id.to_bytes(8, "little")
            frame = p_id + payload
            tag = poly1305.Poly1305.generate_tag(key, frame)
            packets.append(frame + tag)
            self.client_packet_id += 1
        return packets

    def send(self, data: bytes, token: bytes = b""):
        if self.state not in (ConnectionProtocolState.CONNECTED, ConnectionProtocolState.HANDSHAKE):
            return
        self.logger.info(f"<<< {trail_off(data.decode('utf-8'))}")
        packets = self.__encrypt_and_tag(data, token)
        self.logger.info(f"Sending {len(data)} bytes in {len(packets)} packets")
        for packet in packets:
            self.transport.sendto(packet, None)

    def disconnect(self):
        self.logger.warning("Disconnecting from server...")
        self.transport.close()

    def connection_lost(self, exc):
        self.logger.warning("Connection to server lost")
        self.state = ConnectionProtocolState.ERROR
        self.diconnection_event.set()

    def handle_message(self, pid, message):
        asyncio.gather(*[handler(pid, message) for handler in self.message_handlers])
