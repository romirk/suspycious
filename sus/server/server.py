"""
SUS server implementation.
"""

import asyncio
import logging
import os.path
from socket import gethostname
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sus.common.util import Address, ConnectionID, MessageCallback, Wallet
from sus.server.protocol import OnePortProtocol


class SusServer:
    """
    This class is responsible for managing the server.
    """
    __protocol: OnePortProtocol

    __GARBAGE_COLLECTOR_INTERVAL = 5  # seconds

    def __init__(self, addr: Address, psks: str):
        """
        Initializes the server.
        :param addr: Tuple containing the address and port to listen on
        :param psks: Hex encoded private key
        """
        self.__addr = addr
        self.__logger = logging.getLogger("gatekeeper")

        if not psks or len(psks) != 64:
            self.__logger.warning("Invalid or empty private key provided. Generating a new key pair.")
            self.__psks = X25519PrivateKey.generate()
        else:
            self.__psks = X25519PrivateKey.from_private_bytes(bytes.fromhex(psks))
        self.__ppks = self.__psks.public_key()

        if not os.path.exists("server.pub"):
            self.__logger.warning("Server key not found, creating a new one")

            # presumably, this is the first time the server is run.
            # print a helpful message to the user.
            message = f"""
            SUS
            ~~~
            Welcome to SUS! This is the first time you're running the server.
            A new server key has been generated for you. Please distribute this
            key to your clients so that they can connect to the server:
            \033[33m{self.__ppks.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}\033[0m
            
            You can find this key in the file server.pub in the current directory.
            
            If you're using the official SUS client, you can use the following command
            to connect to the server:
            sus client -k server.pub -s {gethostname()} -p {self.__addr[1]}
            
            If you're using a custom client, please refer to the documentation for
            instructions on how to connect to the server.
            """
            self.__logger.info(message)

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
                await asyncio.sleep(SusServer.__GARBAGE_COLLECTOR_INTERVAL)
                # if not self.__protocol.has_clients:
                #     self.__logger.warning("No clients connected, shutting down")
                #     self.stop()
                #     return
                self.__logger.debug(f"{len(self.__protocol)} clients connected")
                self.__protocol.clean()
        except asyncio.CancelledError:
            pass

    async def spin(self, message_handlers: Iterable[MessageCallback] = None):
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

        # if message handlers were empty, warn the user.
        if not message_handlers:
            self.__logger.warning("No message handlers were provided. You will not receive any messages from clients.")
            self.__logger.warning("Please specify message handlers when calling start().")
        # we're done here, wait for the protocol to close.
        try:
            await self.idler()
        except asyncio.CancelledError:
            self.stop()
        finally:
            gc_task.cancel()

    def send(self, msg: bytes, conn_id: ConnectionID):
        """
        Schedules a message to be sent to a client.
        :param msg: Message to send
        :param conn_id: Connection ID of the client
        """
        self.__protocol.send(conn_id, msg)

    def stop(self):
        """
        Stops the server.
        """
        self.__logger.warning("Shutting down")
        self.__protocol.close()

    async def idler(self):
        """
        waits for the server to stop.
        """
        while not self.__protocol.closed.is_set():
            await asyncio.sleep(1)
