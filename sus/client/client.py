"""
The client class.
"""

import asyncio
import logging
import socket
from os import urandom
from typing import Iterable

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.client.protocol import SusClientProtocol
from sus.common.exceptions import MalformedPacket
from sus.common.util import ConnectionID, ConnectionState, MessageHandler, Wallet


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
        return hasattr(self, "protocol") and self.protocol.state == ConnectionState.CONNECTED

    async def start(self, handlers: Iterable[MessageHandler] = None):
        """
        This coroutine is responsible for starting the client. Blocks until the client is connected.
        It also registers message handlers, called when a message is received.
        :param handlers:
        :return:
        """
        await self.connect()
        for handler in handlers or []:
            self.protocol.add_message_handler(handler)

    def __key_exchange(self, epks_ns_port: bytes, wallet: Wallet) -> Wallet:
        """
        This function is responsible for performing the key exchange.
        :param epks_ns_port: received (epks, ns, port) from server
        :param wallet: wallet containing the client's keys
        :return: wallet containing the shared secret
        """

        if len(epks_ns_port) != 40:
            raise MalformedPacket("Invalid key response length")
        # 4. receive (epks, ns, port) from server
        wallet.epks = X25519PublicKey.from_public_bytes(epks_ns_port[:32])
        wallet.ns = epks_ns_port[32:40]
        self.__logger.info("received keys, starting handshake")
        # 5. compute ecps = X25519(eskc, ppks)
        ecps = wallet.eskc.exchange(wallet.ppks)
        eces = wallet.eskc.exchange(wallet.epks)
        # 6. compute key = H(eces, ecps, nc, ns, ppks, epks, epkc)
        wallet.shared_secret = blake3(
            eces + ecps + wallet.nc + wallet.ns +
            wallet.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw)).digest()
        self.__logger.info("shared secret: %s", wallet.shared_secret.hex())

        # 7. compute token = H(epkc, epks, nc, ns)
        self.__logger.info("\n".join([
            f"epkc: {wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}",
            f"epks: {wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}",
            f"nc: {wallet.nc.hex()}",
            f"ns: {wallet.ns.hex()}"
        ]))
        wallet.token = blake3(wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
                              wallet.nc + wallet.ns).digest()
        return wallet

    async def connect(self):
        """
        This coroutine is responsible for connecting to the server.
        Performs the key exchange and starts the handshake.
        """
        self.__logger.info(f"connecting to server ({self.__addr[0]}:{self.__addr[1]})")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(self.__addr)
        sock.setblocking(False)
        sock.settimeout(5)

        eskc = X25519PrivateKey.generate()
        epkc = eskc.public_key()
        nc = urandom(8)
        wallet = Wallet(ppks=self.__ppks, eskc=eskc, epkc=epkc, nc=nc)

        sock.send(b"\x00" * 4 + wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) + wallet.nc)
        data = sock.recv(40)

        wallet = self.__key_exchange(data, wallet)
        conn_id = self.__gen_connection_id(wallet)
        self.__logger.debug(f"connection ID: {conn_id}")

        self.__logger.info("received keys, starting handshake")

        _, self.protocol = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: SusClientProtocol(wallet, conn_id, self.__protocol_id),
            sock=sock
        )
        await self.protocol.handshake_event.wait()
        # return True

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
            await self.protocol.disconnection_event.wait()
        except asyncio.CancelledError:
            self.__logger.info("exiting...")
