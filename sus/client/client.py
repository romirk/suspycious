import asyncio
import logging
import socket
from os import urandom
from typing import Iterable

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from clicker.client.protocol import ClickerClientProtocol
from clicker.common.exceptions import MalformedPacket
from clicker.common.util import ConnectionProtocolState, MessageHandler, Wallet


class SusClient:
    protocol: ClickerClientProtocol

    def __init__(self, addr: tuple[str, int], ppks: str, protocol_id: bytes):
        self.server_addr = addr
        self.ppks = X25519PublicKey.from_public_bytes(bytes.fromhex(ppks))
        self.protocol_id = protocol_id

        self.logger = logging.getLogger(f"susclicker")

    def __del__(self):
        self.disconnect()

    @property
    def connected(self):
        return hasattr(self, "protocol") and self.protocol.state == ConnectionProtocolState.CONNECTED

    async def start(self, handlers: Iterable[MessageHandler] = None):
        await self.connect()
        for handler in handlers or []:
            self.protocol.add_message_handler(handler)

    def __key_exchange(self, epks_ns_port: bytes, wallet: Wallet):

        if len(epks_ns_port) != 40:
            raise MalformedPacket("Invalid key response length")
        # 4. receive (epks, ns, port) from server
        wallet.epks = X25519PublicKey.from_public_bytes(epks_ns_port[:32])
        wallet.ns = epks_ns_port[32:40]
        self.logger.info("received keys, starting handshake")
        # 5. compute ecps = X25519(eskc, ppks)
        ecps = wallet.eskc.exchange(wallet.ppks)
        eces = wallet.eskc.exchange(wallet.epks)
        # 6. compute key = H(eces, ecps, nc, ns, ppks, epks, epkc)
        wallet.shared_secret = blake3(
            eces + ecps + wallet.nc + wallet.ns +
            wallet.ppks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epks.public_bytes(Encoding.Raw, PublicFormat.Raw) +
            wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw)).digest()
        self.logger.info("shared secret: %s", wallet.shared_secret.hex())

        # 7. compute token = H(epkc, epks, nc, ns)
        self.logger.info("\n".join([
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
        self.logger.info(f"connecting to server ({self.server_addr[0]}:{self.server_addr[1]})")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(self.server_addr)
        sock.setblocking(False)
        sock.settimeout(5)

        eskc = X25519PrivateKey.generate()
        epkc = eskc.public_key()
        nc = urandom(8)
        wallet = Wallet(ppks=self.ppks, eskc=eskc, epkc=epkc, nc=nc)

        # try:
        sock.send(wallet.epkc.public_bytes(Encoding.Raw, PublicFormat.Raw) + wallet.nc)
        data = sock.recv(40)
        # except (ConnectionError, TimeoutError):
        #     self.logger.error("failed to connect to server")
        # return False

        wallet = self.__key_exchange(data, wallet)

        self.logger.info("received keys, starting handshake")

        _, self.protocol = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: ClickerClientProtocol(wallet, self.protocol_id),
            sock=sock
        )
        await self.protocol.handshake_event.wait()
        # return True

    def send(self, data: bytes):
        if not self.protocol:
            self.logger.warning("not connected to server")
            return
        self.protocol.send(data)

    def disconnect(self):
        if not hasattr(self, "protocol"):
            self.logger.warning("not connected to server")
            return
        try:
            asyncio.get_running_loop()
            self.protocol.disconnect()
        except RuntimeError:  # not running in event loop
            pass
        self.logger.info(f"disconnected from server ({self.server_addr[0]}:{self.server_addr[1]})")

    async def keep_alive(self):
        if not hasattr(self, "protocol"):
            self.logger.warning("not connected to server")
            return
        try:
            await self.protocol.diconnection_event.wait()
        except asyncio.CancelledError:
            self.logger.info("exiting...")
