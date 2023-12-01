"""
This module contains all the exceptions used in the sus package.
"""
from random import choice


class CatastrophicFailure(Exception):
    """Raised when something goes horribly wrong"""

    def __init__(self, message: str = ""):
        prefix = choice(["Catastrophic", "Cataclysmic", "Devastating", "Disastrous", "Fatal", "Ruinous", "Tragic"])
        super().__init__(prefix + " failure: " + message)


class MalformedKeyRequest(Exception):
    """Raised when a key request is malformed"""
    pass


class MalformedPacket(Exception):
    """Raised when a packet is malformed"""
    pass


class HandshakeError(Exception):
    """Raised when a handshake fails"""
    pass
