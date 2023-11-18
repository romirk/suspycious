import asyncio
import logging
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.common.util import MessageHandler, Wallet
from clicker.server.protocol import OnePortProtocol


class SusServer:
    protocol: OnePortProtocol

    def __init__(self, addr: tuple[str, int], psks: str):
        self.addr = addr
        self.logger = logging.getLogger("gatekeeper")

        self.psks = X25519PrivateKey.from_private_bytes(bytes.fromhex(psks))
        self.ppks = self.psks.public_key()

        with open("server.pub", "w") as f:
            f.write(self.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex())

    async def __garbage_collector(self):
        while not self.protocol.closed.is_set():
            try:
                await asyncio.sleep(10)
                self.protocol.clean()
            except asyncio.CancelledError:
                self.logger.info("Garbage collector exiting...")
                return

    async def start(self, message_handlers: Iterable[MessageHandler] = None):
        self.logger.info("Starting server")
        self.logger.info(f"public key: {self.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}")

        wallet = Wallet(ppks=self.ppks, psks=self.psks)

        _, self.protocol = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: OnePortProtocol(wallet, message_handlers if message_handlers else []),
            self.addr)

        gc_task = None
        try:
            gc_task = asyncio.create_task(self.__garbage_collector())
            await self.protocol.closed.wait()
        except asyncio.CancelledError:
            self.logger.info("Server stopped")
        finally:
            if gc_task:
                gc_task.cancel()
            self.protocol.close()

    async def send(self, addr: tuple[str, int], msg: bytes):
        await self.protocol.send(msg, addr)

    async def stop(self):
        self.logger.warning("Shutting down")
        self.protocol.close()
