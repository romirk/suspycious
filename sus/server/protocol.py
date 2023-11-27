"""
This module contains the OnePortProtocol class.
"""
import asyncio
import logging
from typing import Iterable

from sus.common.exceptions import HandshakeError, MalformedPacket
from sus.common.util import Address, ConnectionID, MessageHandler, Wallet
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

        self.__addr_to_conn_id: dict[Address, ConnectionID] = dict()
        self.__clients: dict[ConnectionID, ClientHandler] = dict()
        # noinspection SpellCheckingInspection
        self.__logger = logging.getLogger(f"oneportsus")

        self.closed = asyncio.Event()

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.__transport = transport
        # noinspection SpellCheckingInspection
        self.__logger.info(f"Listening on port {transport.get_extra_info('sockname')[1]}")

    def error_received(self, exc):
        self.__logger.exception(exc)

    def datagram_received(self, data, addr):
        connection_id = int.from_bytes(data[:4], "little")
        data = data[4:]
        if connection_id not in self.__clients:
            try:
                c = ClientHandler(addr, self.__transport, self.__wallet, self.__message_handlers,
                                  async_send=self.__async_send)
                c.handle(data)
            except (HandshakeError, MalformedPacket):
                self.__logger.error(f"Handshake failed with {addr}")
                return
            self.__clients[c.connection_id] = c
            return

        handler = self.__clients[connection_id]

        try:
            handler.handle(data)
        except MalformedPacket:
            self.__logger.error(f"Malformed packet from {addr}")
            del self.__clients[connection_id]

    def send(self, conn_id: ConnectionID, data: bytes):
        if conn_id not in self.__clients:
            self.__logger.error(f"Attempted to send to {conn_id} but they are not connected")
            return
        self.__clients[conn_id].send(conn_id.to_bytes(4, "little") + data)

    def add_message_handler(self, handler: MessageHandler, addr: tuple[str, int]):
        self.__clients[self.__addr_to_conn_id[addr]].add_message_handler(handler)

    def clean(self):
        """
        Removes inactive clients.
        """
        for addr, conn_id in list(self.__addr_to_conn_id.items()):
            client = self.__clients.get(conn_id, None)
            if client is None:
                del self.__addr_to_conn_id[addr]
                continue
            if not client.is_alive:
                self.__logger.warning(f"Removing inactive client {addr}")
                del self.__addr_to_conn_id[addr]
                self.__clients[conn_id].disconnect()
                del self.__clients[conn_id]

    def close(self):
        self.__transport.close()

    def connection_lost(self, exc):
        self.__logger.warning("Connection closed")
        self.closed.set()
