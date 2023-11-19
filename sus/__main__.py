import argparse
import asyncio

from sus.common.util import logger_config

parser = argparse.ArgumentParser(description="SUS")
command = parser.add_subparsers(dest="command")

server = command.add_parser("server", help="Run SUS server")
server.add_argument("-k", "--private-key", help="Private key file", required=True)
server.add_argument("-p", "--port", help="Server port", default=42069, type=int)

client = command.add_parser("client", help="Run SUS client")
client.add_argument("-k", "--public-key", help="Public key", required=True)
client.add_argument("-s", "--server", help="Server address", default="localhost")
client.add_argument("-p", "--port", help="Server port", default=42069, type=int)
client.add_argument("-a", "--application-protocol", help="Application protocol", default=b"cliq")

args = parser.parse_args()

if args.command == "client":
    from sus.client import SusClient

    logger_config()
    client = SusClient((args.server, int(args.port)), open(args.public_key, "r").read(), args.application_protocol)
    asyncio.run(client.start())
else:
    from sus.server import SusServer

    logger_config()
    server = SusServer(("0.0.0.0", args.port), open(args.private_key, "r").read())
    asyncio.run(server.start())
