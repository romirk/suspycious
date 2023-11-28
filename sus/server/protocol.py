"""
This module contains the OnePortProtocol class.
"""
import asyncio
import logging
from typing import Iterable

from sus.common.exceptions import HandshakeError, MalformedPacket
from sus.common.util import ConnectionID, MessageHandler, Wallet
from sus.server.handler import ClientHandler


class OnePortProtocol(asyncio.DatagramProtocol):
    """
    This class is responsible for handling the UDP protocol.
    It matches incoming packets to clients and handles the handshake.
    """
    __transport: asyncio.DatagramTransport

    def __init__(self, wallet: Wallet, message_handlers: Iterable[MessageHandler], async_send: bool = False):
        super().__init__()
        self.__wallet = wallet
        self.__message_handlers = message_handlers
        self.__async_send = async_send

        self.__clients: dict[ConnectionID, ClientHandler] = dict()
        # noinspection SpellCheckingInspection
        self.__logger = logging.getLogger(f"oneportsus")

        self.closed = asyncio.Event()

    @property
    def has_clients(self):
        return bool(self.__clients)

    def __len__(self):
        return len(self.__clients)

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.__transport = transport
        # noinspection SpellCheckingInspection
        self.__logger.info(f"Listening on port {transport.get_extra_info('sockname')[1]}")

    def error_received(self, exc):
        self.__logger.exception(exc)

    def datagram_received(self, data, addr):
        connection_id = int.from_bytes(data[:4], "little", signed=False)
        data = data[4:]
        if not connection_id:
            try:
                c = ClientHandler(addr, self.__transport, self.__wallet, self.__message_handlers,
                                  async_send=self.__async_send)
                c.handle(data)
            except (HandshakeError, MalformedPacket):
                self.__logger.error(f"Handshake failed with {addr}")
                del c
                return

            self.__clients[c.connection_id] = c
            return

        try:
            handler = self.__clients[connection_id]
        except KeyError:
            self.__logger.error(f"Received packet from unknown connection ID {connection_id}")
            return

        try:
            handler.handle(data)
        except HandshakeError:
            self.__logger.error(f"Handshake failed with {addr}")
            del self.__clients[connection_id]
        except MalformedPacket:
            self.__logger.error(f"Malformed packet from {addr}")

    def send(self, conn_id: ConnectionID, data: bytes):
        if conn_id not in self.__clients:
            self.__logger.error(f"Attempted to send to {conn_id} but they are not connected")
            return
        self.__clients[conn_id].send(conn_id.to_bytes(4, "little") + data)

    # def add_message_handler(self, handler: MessageHandler, addr: tuple[str, int]):
    #     self.__clients[self.__addr_to_conn_id[addr]].add_message_handler(handler)

    def clean(self):
        """
        Removes inactive clients.
        """
        self.__logger.debug("Cleaning up inactive clients")
        for conn_id, handler in self.__clients.items():
            if not handler.is_alive:
                self.__logger.info(f"Client {conn_id} timed out")
                handler.disconnect()
                del self.__clients[conn_id]

    def close(self):
        self.__logger.info("Closing")
        self.__transport.close()

    def connection_lost(self, exc):
        self.__logger.warning("Connection closed")
        self.closed.set()
