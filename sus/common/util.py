"""
Utility functions and classes.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from logging import WARNING, basicConfig, getLogger
from typing import Any, Awaitable, Callable, Optional, Type, TypeAlias

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

Address = tuple[str, int]
MessageHandler: Type = Callable[[Address, int, bytes], Awaitable[Any]]


def trail_off(msg: str, length: int = 40):
    """
    Truncates a string to a given length and adds an ellipsis.
    :param msg: message to truncate
    :param length: maximum length of the string (including ellipsis)
    :return: truncated string
    """
    if len(msg) > length:
        msg = msg[:length - 3] + "..."
    return msg


def logger_config():
    """Default logger configuration."""
    basicConfig(level=WARNING, format="%(asctime)s | %(name)s - %(levelname)8s : %(message)s")
    getLogger('asyncio').setLevel(WARNING)


def now():
    """Returns the current timestamp."""
    return datetime.now().timestamp()


@dataclass
class Wallet:
    """
    Convenience class for storing keys and other data.
    """

    ppks: X25519PublicKey
    """The server's public key."""
    psks: Optional[X25519PrivateKey] = None
    """The server's private key."""

    esks: Optional[X25519PrivateKey] = None
    """ephemeral server private key"""
    epks: Optional[X25519PublicKey] = None
    """ephemeral server public key"""
    ns: Optional[bytes] = None
    """server nonce"""

    eskc: Optional[X25519PrivateKey] = None
    """ephemeral client private key"""
    epkc: Optional[X25519PublicKey] = None
    """ephemeral client public key"""
    nc: Optional[bytes] = None
    """client nonce"""

    token: Optional[bytes] = None
    """Verification token"""
    shared_secret: Optional[bytes] = None
    """Shared secret"""


ConnectionID: TypeAlias = int


class ConnectionState(Enum):
    """
    Enum representing the state of the connection.
    """
    ERROR = -1
    INITIAL = 0
    HANDSHAKE = 1
    CONNECTED = 2
    DISCONNECTED = 3
