import argparse
import asyncio
import logging

from clicker import SusClient
from clicker.common.util import Address, logger_config

logger = logging.getLogger("app")


async def msg_handler(_: Address, msg_id: int, msg: bytes):
    logger.info(f"Received message {msg_id}: {msg.decode()}")


async def main(host: str, port: int, key: str):
    logger_config()

    with open(key, "r") as f:
        key = f.read()
        print(f"Using public key \033[36m{key}\033[0m")
    client = SusClient((host, port), key, b"cliq")
    try:
        await client.start([msg_handler])
    except (TimeoutError, ConnectionError):
        exit(1)
    client.send(b"hello world")
    client.send(b"goodbye world")
    await client.keep_alive()
    exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clicker client")
    parser.add_argument("--host", type=str, default="localhost", help="host")
    parser.add_argument("--port", type=int, default=42069, help="port")
    parser.add_argument("--key", type=str, default="server.pub", help="key file")
    args = parser.parse_args()
    asyncio.run(main(args.host, args.port, args.key))
