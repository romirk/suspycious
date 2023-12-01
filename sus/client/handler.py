import asyncio
from os import urandom
from typing import Iterable

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.common.exceptions import CatastrophicFailure, HandshakeError
from sus.common.handler import BaseEndpoint
from sus.common.util import Address, ConnectionState, MessageCallback, Wallet


class ClientEndpoint(BaseEndpoint):
    """
    This class is responsible for handling clients.
    One instance of this class is created for each client.
    """

    def __init__(self, addr: Address, transport: asyncio.DatagramTransport, wallet: Wallet,
                 message_callbacks: Iterable[MessageCallback], app_id: bytes, max_packets: int = 100):
        super().__init__(addr, transport, app_id, wallet, message_callbacks, max_packets)

        self._logger.info(f"New client")

        wallet.esks = X25519PrivateKey.generate()
        wallet.epks = wallet.esks.public_key()
        wallet.ns = urandom(8)

    def _initial(self, data: bytes):
        if len(data) != 40:
            raise HandshakeError("Invalid key response length")

        wallet = self._wallet

        wallet.epks = X25519PublicKey.from_public_bytes(data[:32])
        wallet.ns = data[32:40]
        self._logger.info("received keys, starting handshake")

        ecps = wallet.eskc.exchange(wallet.ppks)
        eces = wallet.esks.exchange(wallet.epks)
        self._gen_secrets(ecps, eces)

        wallet.token = blake3(wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.nc + wallet.ns).digest()

        self.__con_id = self._gen_connection_id()
        self.__state = ConnectionState.HANDSHAKE
        self.send_now(self._app_id, wallet.token)

        # we don't expect a respose from the server, so we can just go ahead and start the connection
        self.__state = ConnectionState.CONNECTED

    def _handshake(self, data: bytes) -> None:
        # nothing to do in a handshake, this should never be called
        raise CatastrophicFailure("This should never happen")

    def _error(self, data: bytes):
        self._logger.error(f"Received in error state: {data.decode()}")

    def _disconnected(self, data: bytes):
        self._logger.warning(f"Received in disconnected state: {data.decode()}")
