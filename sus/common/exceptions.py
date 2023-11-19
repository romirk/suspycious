"""
This module contains all the exceptions used in the sus package.
"""


class MalformedKeyRequest(Exception):
    """Raised when a key request is malformed"""
    pass


class MalformedPacket(Exception):
    """Raised when a packet is malformed"""
    pass


class HandsakeError(Exception):
    """Raised when a handshake fails"""
    pass
