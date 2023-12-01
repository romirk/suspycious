"""
The client class.
"""

import asyncio
import logging
import socket
from typing import Iterable

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.client.protocol import SusClientProtocol
from sus.common.util import ConnectionID, MessageCallback, Wallet


class SusClient:
    """
    This class is responsible for managing the client.
    """
    protocol: SusClientProtocol

    def __init__(self, addr: tuple[str, int], ppks: str, protocol_id: bytes):
        """
        Initializes the client.
        :param addr: Server address
        :param ppks: Server public key
        :param protocol_id:  Protocol ID (any bytestring)
        """
        self.__addr = addr
        self.__ppks = X25519PublicKey.from_public_bytes(bytes.fromhex(ppks))
        self.__protocol_id = protocol_id

        self.__logger = logging.getLogger(f"SusClient")

    def __del__(self):
        self.disconnect()

    @staticmethod
    def __gen_connection_id(wallet: Wallet, channel_id: int = 0) -> ConnectionID:
        # figure out a way to deterministically generate connection_id
        # for now, this just hashes the shared secret with the channel ID
        return int.from_bytes(
            blake3(
                wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                int.to_bytes(channel_id)
            ).digest()[:4], "little", signed=False)

    @property
    def connected(self):
        """
        True if the client is connected to the server.
        """
        return hasattr(self, "protocol") and self.protocol.is_connected

    async def start(self, handlers: Iterable[MessageCallback] = None):
        """
        This coroutine is responsible for starting the client. Blocks until the client is connected.
        It also registers message handlers, called when a message is received.
        :param handlers:
        :return:
        """

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(self.__addr)
        sock.setblocking(False)
        sock.settimeout(5)

        _, self.protocol = await asyncio.wait_for(asyncio.get_running_loop().create_datagram_endpoint(
            lambda: SusClientProtocol(self.__addr, self.__ppks, self.__protocol_id, handlers),
            sock=sock), 5)

        await self.protocol.wait_for_connection()

    def send(self, data: bytes):
        """
        Sends a message to the server.
        :param data: message to send as bytes
        """
        if not self.protocol:
            self.__logger.warning("not connected to server")
            return
        self.protocol.send(data)

    def disconnect(self):
        """
        Disconnects from the server.
        """
        if not hasattr(self, "protocol"):
            self.__logger.warning("not connected to server")
            return
        try:
            asyncio.get_running_loop()
            self.protocol.disconnect()
        except RuntimeError:  # not running in event loop
            pass
        self.__logger.info(f"disconnected from server ({self.__addr[0]}:{self.__addr[1]})")

    async def keep_alive(self):
        """
        Convenience coroutine that waits until the client is disconnected.
        """
        if not hasattr(self, "protocol"):
            self.__logger.warning("not connected to server")
            return
        try:
            await self.protocol.closed.wait()
        except asyncio.CancelledError:
            self.__logger.info("exiting...")
