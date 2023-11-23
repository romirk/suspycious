"""
SUS server implementation.
"""

import asyncio
import logging
import os.path
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.common.util import Address, MessageHandler, Wallet
from sus.server.protocol import OnePortProtocol

GARABAGE_COLLECTOR_INTERVAL = 15  # seconds


class SusServer:
    """
    This class is responsible for managing the server.
    """
    __protocol: OnePortProtocol

    def __init__(self, addr: Address, psks: str):
        """
        Initializes the server.
        :param addr: Tuple containing the address and port to listen on
        :param psks: Hex encoded private key
        """
        self.__addr = addr
        self.__logger = logging.getLogger("gatekeeper")

        if not psks or len(psks) != 64:
            self.__logger.warning("Invalid or empty private key provided. Generating a new one.")
            self.__psks = X25519PrivateKey.generate()
        else:
            self.__psks = X25519PrivateKey.from_private_bytes(bytes.fromhex(psks))
        self.__ppks = self.__psks.public_key()

        if not os.path.exists("server.pub"):
            self.__logger.warning("Server key not found, creating a new one")

            # presumably, this is the first time the server is run.
            # print a helpful message to the user.
            print("\nSus\n===\n")
            print("Welcome to SUS!")
            print("This is the first time you're running the server. A new keypair will be generated.")
            print("Please copy the following public key to the client:")
            print(self.__ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
            print("")

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
                await asyncio.sleep(GARABAGE_COLLECTOR_INTERVAL)
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

        # create a protocol instance, this will handle all incoming packets
        _, self.__protocol = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: OnePortProtocol(wallet, message_handlers if message_handlers else []),
            self.__addr)

        # start the garbage collector.
        gc_task = asyncio.create_task(self.__garbage_collector())

        # if message handlers were emoty, warn the user.
        if not message_handlers:
            self.__logger.warning("No message handlers were provided. You will not receive any messages from clients.")
            self.__logger.warning("Please specify message handlers when calling start().")
        # we're done here, wait for the protocol to close.
        try:
            await self.__protocol.closed.wait()
        except asyncio.CancelledError:
            self.stop()
        finally:
            gc_task.cancel()

    def send(self, addr: Address, msg: bytes):
        """
        Schedules a message to be sent to a client.
        :param addr: Client address
        :param msg: Message to send
        """
        self.__protocol.send(msg, addr)

    def stop(self):
        """
        Stops the server.
        """
        self.__logger.warning("Shutting down")
        self.__protocol.close()
