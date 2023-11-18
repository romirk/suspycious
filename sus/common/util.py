from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from logging import DEBUG, basicConfig
from typing import Any, Awaitable, Callable, Optional, Type

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

Address = tuple[str, int]
MessageHandler: Type = Callable[[Address, int, bytes], Awaitable[Any]]


def trail_off(msg: str, length: int = 40):
    if len(msg) > length:
        msg = msg[:length - 3] + "..."
    return msg


def logger_config():
    basicConfig(level=DEBUG, format="%(asctime)s | %(name)s - %(levelname)8s : %(message)s")


def now():
    return datetime.now().timestamp()


@dataclass
class Wallet:
    ppks: X25519PublicKey
    psks: Optional[X25519PrivateKey] = None

    esks: Optional[X25519PrivateKey] = None
    epks: Optional[X25519PublicKey] = None
    ns: Optional[bytes] = None

    eskc: Optional[X25519PrivateKey] = None
    epkc: Optional[X25519PublicKey] = None
    nc: Optional[bytes] = None

    token: Optional[bytes] = None
    shared_secret: Optional[bytes] = None


class ConnectionProtocolState(Enum):
    ERROR = -1
    INITIAL = 0
    HANDSHAKE = 1
    CONNECTED = 2
    DISCONNECTED = 3
