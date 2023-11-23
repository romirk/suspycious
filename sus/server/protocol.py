"""
This module contains the OnePortProtocol class.
"""
import asyncio
import logging
from typing import Iterable

from sus.common.exceptions import HandsakeError, MalformedPacket
from sus.common.util import Address, ConnectionID, MessageHandler, Wallet
from sus.server.handler import ClientHandler


class OnePortProtocol(asyncio.DatagramProtocol):
    """
    This class is responsible for handling the UDP protocol.
    It matches incoming packets to clients and handles the handshake.
    """
    __transport: asyncio.DatagramTransport

    def __init__(self, wallet: Wallet, message_handlers: Iterable[MessageHandler]):
        super().__init__()
        self.__wallet = wallet
        self.__message_handlers = message_handlers

        self.__addr_to_conn_id: dict[Address, ConnectionID] = dict()
        self.__clients: dict[ConnectionID, ClientHandler] = dict()
        self.__logger = logging.getLogger(f"oneportsus")

        self.closed = asyncio.Event()

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.__transport = transport
        self.__logger.info(f"Listening on port {transport.get_extra_info('sockname')[1]}")

    def error_received(self, exc):
        self.__logger.exception(exc)

    def datagram_received(self, data, addr):
        if addr not in self.__addr_to_conn_id:
            try:
                c = ClientHandler(addr, self.__transport, self.__wallet, self.__message_handlers)
                c.handle(data)
            except (HandsakeError, MalformedPacket):
                self.__logger.error(f"Handshake failed with {addr}")
                return
            self.__addr_to_conn_id[addr] = c.connection_id
            self.__clients[c.connection_id] = c
            return

        connection_id = self.__addr_to_conn_id[addr]
        handler = self.__clients[connection_id]

        try:
            handler.handle(data)
        except MalformedPacket:
            self.__logger.error(f"Malformed packet from {addr}")
            del self.__clients[connection_id]

    def send(self, data: bytes, addr: tuple[str, int]):
        if addr not in self.__clients:
            self.__logger.error(f"Attempted to send to {addr} but they are not connected")
            return
        self.__clients[self.__addr_to_conn_id[addr]].send(data)

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
