"""
This module contains the OnePortProtocol class.
"""
import asyncio
import logging
from typing import Iterable

from sus.common.exceptions import HandsakeError, MalformedPacket
from sus.common.util import MessageHandler, Wallet
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

        self.__clients: dict[tuple[str, int], ClientHandler] = dict()
        self.__logger = logging.getLogger(f"OnePort")

        self.closed = asyncio.Event()

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.__transport = transport
        self.__logger.info(f"Listening on port {transport.get_extra_info('sockname')[1]}")

    def error_received(self, exc):
        self.__logger.exception(exc)

    def datagram_received(self, data, addr):
        if addr not in self.__clients:
            try:
                c = ClientHandler(addr, self.__transport, self.__wallet, self.__message_handlers)
            except (HandsakeError, MalformedPacket):
                self.__logger.error(f"Handshake failed with {addr}")
                return
            self.__clients[addr] = c

        handler = self.__clients[addr]

        try:
            handler.handle(data)
        except HandsakeError:
            self.__logger.error(f"Handshake failed with {addr}")
            del self.__clients[addr]
            self.close()
        except MalformedPacket:
            self.__logger.error(f"Malformed packet from {addr}")
            del self.__clients[addr]

    async def send(self, data: bytes, addr: tuple[str, int]):
        if addr not in self.__clients:
            self.__logger.error(f"Attempted to send to {addr} but they are not connected")
            return
        await self.__clients[addr].send(data)

    def add_message_handler(self, handler: MessageHandler, addr: tuple[str, int]):
        self.__clients[addr].add_message_handler(handler)

    def clean(self):
        for addr in list(self.__clients.keys()):
            if not self.__clients[addr].is_alive:
                del self.__clients[addr]

    def close(self):
        self.__transport.close()

    def connection_lost(self, exc):
        self.__logger.info("Connection closed")
        self.closed.set()
