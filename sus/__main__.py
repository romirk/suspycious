import argparse
import asyncio

from sus.common.util import logger_config


def main():
    opts = parse_args()
    if opts.command == "client":
        from sus.client import SusClient

        logger_config()
        client = SusClient((opts.server, int(opts.port)),
                           open(opts.public_key, "r").read().strip(),
                           opts.application_protocol.encode())
        asyncio.run(client.start())
        client.send(b"fuckyou" * 3000)
    else:
        from sus.server import SusServer

        logger_config()
        server = SusServer(("0.0.0.0", opts.port),
                           open(opts.private_key, "r").read().strip() if opts.private_key else None)
        asyncio.run(server.start())


def parse_args():
    parser = argparse.ArgumentParser(description="SUS")
    command = parser.add_subparsers(dest="command", required=True, description="command")

    server_parser = command.add_parser("server", help="Run SUS server")
    server_parser.add_argument("-k", "--private-key", help="Private key file", default=None, type=str)
    server_parser.add_argument("-p", "--port", help="Server port", default=42069, type=int)

    client_parser = command.add_parser("client", help="Run SUS client")
    client_parser.add_argument("-k", "--public-key", help="Public key", required=True)
    client_parser.add_argument("-s", "--server", help="Server address", default="localhost")
    client_parser.add_argument("-p", "--port", help="Server port", default=42069, type=int)
    client_parser.add_argument("-a", "--application-protocol", help="Application protocol", default="sus", type=str)

    return parser.parse_args()


if __name__ == '__main__':
    main()
