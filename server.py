import argparse
import asyncio

from clicker import SusServer
from clicker.common.util import logger_config


def main(key_file: str):
    logger_config()
    with open(key_file, "r") as f:
        psks = f.read()
    server = SusServer(("0.0.0.0", 42069), psks)

    # create event loop
    asyncio.run(server.start())
    print("done")
    exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clicker server")
    parser.add_argument("key", type=str, default="server.key", help="key file")
    args = parser.parse_args()
    main(args.key)
