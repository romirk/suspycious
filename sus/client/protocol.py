"""
The client protocol is responsible for handling the connection to the server.
It encrypts and decrypts messages, and handles the handshake. It also handles
splitting messages into packets and reassembling them.
"""

import asyncio
import logging
from os import urandom
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.client.handler import ClientEndpoint
from sus.common.util import Address, ConnectionState, MessageCallback, Wallet


class SusClientProtocol(asyncio.DatagramProtocol):
    """
    This class is responsible for handling the UDP protocol.
    """
    __transport: asyncio.DatagramTransport
    __handler: ClientEndpoint
    __wallet: Wallet

    def __init__(self, addr: Address, ppks: X25519PublicKey, protocol_id: bytes,
                 message_handlers: Iterable[MessageCallback], ):
        super().__init__()

        self.__addr = addr
        self.__ppks = ppks
        self.__protocol_id = protocol_id
        self.__message_handlers = message_handlers
        self.__logger = logging.getLogger(f"SusClientProtocol")

        self.connected = asyncio.Event()
        self.closed = asyncio.Event()

    @property
    def is_connected(self):
        try:
            return self.__handler.state in (ConnectionState.CONNECTED, ConnectionState.HANDSHAKE)
        except AttributeError:
            return False

    async def wait_for_connection(self):
        for _ in range(5):
            await asyncio.sleep(1)
            if self.is_connected:
                self.__logger.info("Connected to server")
                return
        if not self.is_connected:
            self.__logger.error(f"Connection timed out: {self.__handler.state}")
            self.disconnect()

    def connection_made(self, transport: asyncio.DatagramTransport):
        """
        This function is called when the connection is established.
        :param transport: transport object, used to send and receive packets
        """

        self.__transport = transport

        eskc = X25519PrivateKey.generate()
        epkc = eskc.public_key()
        nc = urandom(8)
        wallet = self.__wallet = Wallet(ppks=self.__ppks, eskc=eskc, epkc=epkc, nc=nc)

        transport.sendto(b"\x00" * 4 + wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) + wallet.nc)
        self.__handler = ClientEndpoint(self.__addr, self.__transport, self.__wallet, self.__message_handlers,
                                        self.__protocol_id)

    def datagram_received(self, data: bytes, _addr: tuple[str, int]):
        """
        This function is called when a packet is received.
        :param data: packet data
        :param _addr: originating address (always the server, unused)
        """

        self.__handler.handle(data)

    def send(self, data: bytes):
        """
        Sends a message to the server.
        :param data: message data
        """
        self.__handler.send(data)

    def disconnect(self):
        """
        Disconnects the client from the server.
        """
        self.__logger.warning("Disconnecting from server...")
        self.__transport.close()

    def connection_lost(self, exc):
        """
        Called when the connection is lost. Sets the disconnection event.
        :param exc: exception raised, if any
        """
        self.__logger.warning("Connection to server lost")
        if exc:
            self.__logger.exception(exc)
        self.closed.set()

    # async def wait_for_connection(self):
    #     try:
    #         await asyncio.wait_for(self.connected.wait(), 5)
    #     except asyncio.TimeoutError:
    #         self.__logger.error("Connection timed out")
    #         self.disconnect()
