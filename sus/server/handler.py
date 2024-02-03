import asyncio
from os import urandom
from typing import Iterable

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.common.exceptions import HandshakeError, MalformedPacket
from sus.common.handler import BaseEndpoint
from sus.common.util import Address, ConnectionState, MessageCallback, Wallet, trail_off


class ServerEndpoint(BaseEndpoint):
    """
    This class is responsible for handling clients.
    One instance of this class is created for each client.
    """

    def __init__(self, addr: Address, transport: asyncio.DatagramTransport, wallet: Wallet,
                 message_handlers: Iterable[MessageCallback], app_id: bytes = b"", max_packets: int = 100):

        super().__init__(addr, transport, app_id, wallet, message_handlers, max_packets)

        self._logger.info(f"New client")

        wallet.esks = X25519PrivateKey.generate()
        wallet.epks = wallet.esks.public_key()
        wallet.ns = urandom(8)

    def _initial(self, data):
        if len(data) != 44:
            self._logger.error(f"Invalid handshake packet ({len(data)} bytes): {data}")
            raise MalformedPacket("Invalid handshake packet")
        data = data[4:]
        wallet = self._wallet
        wallet.epkc = X25519PublicKey.from_public_bytes(data[:32])
        wallet.nc = data[32:]

        self._con_id = self._gen_connection_id()
        self._logger.info(f"connection ID: {self._con_id}")
        self._state = ConnectionState.HANDSHAKE
        self._transport.sendto((wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) + wallet.ns), self._addr)
        self._logger.info("sent keys, waiting for response")

    def _handshake(self, data) -> None:
        if len(data) < 44:
            self._logger.error("Invalid handshake packet")
            self._state = ConnectionState.ERROR
            raise MalformedPacket("Invalid handshake packet")

        wallet = self._wallet

        wallet.token = blake3(wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.nc + wallet.ns).digest()

        client_token = data[12:44]

        self._logger.debug(f"token: {client_token.hex()}")

        if client_token != wallet.token:
            self._logger.debug(f"ours : {self._wallet.token.hex()}")
            self._logger.error("token mismatch!")
            raise HandshakeError("Token mismatch")

        self._logger.debug("token: OK")

        eces = wallet.esks.exchange(wallet.epkc)
        ecps = wallet.psks.exchange(wallet.epkc)
        self._gen_secrets(ecps, eces)

        buffer = self._verify_and_decrypt(data)
        if buffer is None:
            self._state = ConnectionState.ERROR
            raise HandshakeError("Invalid handshake packet")

        messages = self._reform_messages(buffer)

        if not messages:
            self._state = ConnectionState.ERROR
            raise HandshakeError("Invalid handshake packet (protocol)")

        self._state = ConnectionState.CONNECTED
        self._app_id = messages[0]
        self._logger.info("Handshake complete")
        self._logger.debug(f"protocol: {self._app_id.decode('utf-8')}")

    def _disconnected(self, data):
        raise NotImplementedError

    def _error(self, data):
        self._logger.error(f"Received data in error state: {trail_off(data.hex())}")
