# Suspycious

Suspycious is a Python implementation of the Sus protocol. It is a 
secure, asynchronous, and easy to use protocol for sending messages
between two parties.


!!! warning "Pre-alpha software"
    Suspycious is currently in an early stage of development and
    should not be used in production.

## Installation

Suspycious is available on PyPI and can be installed with pip:

```bash
pip install suspycious
```

## Usage

The following example shows how to create a simple Sus network with
a client and a server. The client sends a message to the server and
the server responds with a message.

```python3
import asyncio

from sus import SusServer

server = SusServer(('localhost', 5000), b"my secret key")


async def message_handler(addr: tuple[str, int], p_id: int, message: bytes):
    print(f"Received message from {addr}: {message.decode()}")
    server.send(addr, b"Hello from the server!")


asyncio.run(server.spin([message_handler]))
```

```python3
import asyncio

from sus import SusClient

client = SusClient(('localhost', 5000), b"server public key")
asyncio.run(client.start())
client.send(b"Hello from the client!")
```


