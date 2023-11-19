"""
SUS server implementation.
"""

import asyncio
import logging
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.common.util import Address, MessageHandler, Wallet
from sus.server.protocol import OnePortProtocol


class SusServer:
    """
    This class is responsible for managing the server.
    """
    __protocol: OnePortProtocol

    def __init__(self, addr: Address, psks: str):
        self.__addr = addr
        self.__logger = logging.getLogger("gatekeeper")

        self.__psks = X25519PrivateKey.from_private_bytes(bytes.fromhex(psks))
        self.__ppks = self.__psks.public_key()

        with open("server.pub", "w") as f:
            f.write(self.__ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex())

    @property
    def public_key(self):
        """Server public key"""
        return self.__ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    @property
    def address(self):
        """Server address"""
        return self.__addr

    async def __garbage_collector(self):
        """
        This coroutine is responsible for cleaning up inactive clients.
        """
        try:
            while not self.__protocol.closed.is_set():
                await asyncio.sleep(10)
                self.__protocol.clean()
        except asyncio.CancelledError:
            pass

    async def start(self, message_handlers: Iterable[MessageHandler] = None):
        """
        This coroutine is responsible for starting the server.
        :param message_handlers: An iterable of message handlers, which are called when a message is received.
        """
        self.__logger.info("Starting server")
        self.__logger.info(f"public key: {self.__ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}")

        wallet = Wallet(ppks=self.__ppks, psks=self.__psks)

        _, self.__protocol = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: OnePortProtocol(wallet, message_handlers if message_handlers else []),
            self.__addr)

        gc_task = None
        try:
            gc_task = asyncio.create_task(self.__garbage_collector())
            await self.__protocol.closed.wait()
        except asyncio.CancelledError:
            self.__logger.info("Server stopped")
        finally:
            if gc_task:
                gc_task.cancel()
            self.__protocol.close()

    async def send(self, addr: Address, msg: bytes):
        await self.__protocol.send(msg, addr)

    async def stop(self):
        self.__logger.warning("Shutting down")
        self.__protocol.close()
