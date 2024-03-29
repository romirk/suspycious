"""
Utility functions and classes.
"""
import asyncio
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from logging import DEBUG, WARNING, basicConfig, getLogger
from time import sleep
from typing import Any, Awaitable, Callable, Optional, TypeAlias

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

Address: TypeAlias = tuple[str, int]
ConnectionID: TypeAlias = int
MessageCallback: TypeAlias = Callable[[ConnectionID, bytes], Awaitable[Any]]


class ConnectionState(Enum):
    """
    Enum representing the state of the connection.
    """
    ERROR = -1
    INITIAL = 0
    HANDSHAKE = 1
    CONNECTED = 2
    DISCONNECTED = 3


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


def countdown(sec: int):
    """
    Countdown timer.
    :param sec: number of seconds to count down from
    """
    while sec > 0:
        print(f"\r{sec} ", end="")
        sec -= 1
        sleep(1)
    print("\r   ", end="")


async def countdown_async(sec: int):
    """
    Countdown timer.
    :param sec: number of seconds to count down from
    """
    while sec > 0:
        print(f"\r{sec} ", end="")
        sec -= 1
        await asyncio.sleep(1)
    print("\r   ", end="")


def logger_config():
    """Default logger configuration."""
    # noinspection SpellCheckingInspection
    basicConfig(level=DEBUG, format="%(asctime)s | %(name)s - %(levelname)8s : %(message)s")
    getLogger('asyncio').setLevel(WARNING)


def now():
    """Returns the current timestamp."""
    return datetime.now().timestamp()


def varint(n: int) -> bytes:
    """
    Encodes an integer as a varint
    :param n: integer to encode
    :return: encoded integer
    """
    b = bytearray()
    while n > 127:
        b.append((n & 0x7f) | 0x80)
        n >>= 7
    b.append(n & 0x7f)
    return bytes(b)


def varint_decode(b: bytes) -> tuple[int, int]:
    """
    Decodes a varint into an integer
    :param b: varint to decode
    :return: decoded integer
    """
    n = 0
    _len = 0
    for i, byte in enumerate(b):
        n |= (byte & 0x7f) << (i * 7)
        _len += 1
        if not byte & 0x80:
            break
    return n, _len


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
