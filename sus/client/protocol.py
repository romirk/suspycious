"""
The client protocol is responsible for handling the connection to the server.
It encrypts and decrypts messages, and handles the handshake. It also handles
splitting messages into packets and reassembling them.
"""

import asyncio
import logging
from typing import Iterable, Optional

from cryptography.hazmat.primitives import poly1305
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20

from sus.common.exceptions import MalformedPacket
from sus.common.globals import CLIENT_ENC_NONCE, CLIENT_MAC_NONCE, SERVER_ENC_NONCE, SERVER_MAC_NONCE
from sus.common.util import ConnectionState, MessageHandler, Wallet, now, trail_off


class SusClientProtocol(asyncio.DatagramProtocol):
    """
    This class is responsible for handling the UDP protocol.
    """
    transport: asyncio.DatagramTransport
    state: ConnectionState

    def __init__(self, wallet: Wallet, protcol_id: bytes,
                 handlers: Optional[Iterable[MessageHandler]] = None):
        """
        Initializes the client protocol.
        :param wallet: wallet containing the client's keys
        :param protcol_id: protocol ID (any bytestring)
        :param handlers: message handlers, called when a message is received
        """
        super().__init__()

        self.wallet = wallet
        self.protocol_id = protcol_id
        self.state = ConnectionState.INITIAL

        self.logger = logging.getLogger(f"sus-cl")

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
        """
        This function is called when the connection is established.
        :param transport: transport object, used to send and receive packets
        """
        self.transport = transport
        self.state = ConnectionState.HANDSHAKE
        self.send(self.protocol_id, self.wallet.token)
        self.state = ConnectionState.CONNECTED
        self.last_seen = now()
        self.logger.debug("Handshake complete")
        self.handshake_event.set()

    def datagram_received(self, data: bytes, _addr: tuple[str, int]):
        """
        This function is called when a packet is received.
        :param data: packet data
        :param _addr: originating address (always the server, unused)
        """

        match self.state:
            case ConnectionState.CONNECTED:
                pid, message = self.__verify_and_decrypt(data)
                self.logger.info(f">>> {trail_off(message.decode('utf-8')) if message else None}")
                self.handle_message(pid, message)

    def __verify_and_decrypt(self, data: bytes) -> tuple[None, None] | tuple[int, bytes]:
        """
        This function is responsible for verifying the packet and decrypting it.
        :param data: data to verify and decrypt
        :return: packet ID and message, or None if the packet is invalid
        """
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
        """
        This function is responsible for splitting a message into packets.
        :param data: data to split
        :return: list of packets
        """
        packet_length = self.mtu_estimate - 24
        return [data[i:i + packet_length] for i in range(0, len(data), packet_length)]

    def __encrypt_and_tag(self, data: bytes, token: bytes) -> list[bytes]:
        """
        This function is responsible for encrypting and tagging a message. Uses the ChaCha20-Poly1305 AEAD to
        encrypt and authenticate the message.
        :param data: data to encrypt
        :param token: optional token to include in the first packet
        :return: packets containing the encrypted and tagged message to send to the server
        """
        message_bytes = len(data).to_bytes(4, "little") + data
        packet_length = self.mtu_estimate - 24
        padded_message_bytes = message_bytes  # + b"\x00" * (
        # packet_length - ((len(message_bytes) + len(token)) % packet_length))

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
        """
        This function is responsible for sending a message to the server.
        :param data: data to send
        :param token: token to include in the first packet. DO NOT INCLUDE THE TOKEN IN SUBSEQUENT PACKETS --
                      a MalformedPacket error will be raised!
        :raises MalformedPacket: if the token is included in a subsequent packet
        """
        if self.state not in (ConnectionState.CONNECTED, ConnectionState.HANDSHAKE):
            return
        if token and self.client_packet_id != 0:
            raise MalformedPacket("Token can only be included in the first packet")
        self.logger.info(f"<<< {trail_off(data.decode('utf-8'))}")
        packets = self.__encrypt_and_tag(data, token)
        self.logger.info(f"Sending {len(data)} bytes in {len(packets)} packets")
        for packet in packets:
            self.transport.sendto(packet, None)

    def disconnect(self):
        """
        Disconnects the client from the server.
        """
        self.logger.warning("Disconnecting from server...")
        self.transport.close()

    def connection_lost(self, exc):
        """
        Called when the connection is lost. Sets the disconnection event.
        :param exc: exception raised, if any
        """
        self.logger.warning("Connection to server lost")
        if exc:
            self.logger.exception(exc)
            self.state = ConnectionState.ERROR
        else:
            self.state = ConnectionState.DISCONNECTED
        self.diconnection_event.set()

    def handle_message(self, pid: int, message: bytes):
        """
        Calls all message handlers asynchronously.
        :param pid: packet ID
        :param message: message bytes
        :return:
        """
        asyncio.gather(*[handler(("", 0), pid, message) for handler in self.message_handlers])
