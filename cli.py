import argparse
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from betanet.sdk import (
    make_ticket_params,
    make_ticket_cookie,
    make_ticket_query_and_body,
    open_stream_tcp,
)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="betanet-cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pt = sub.add_parser("ticket")
    pt.add_argument("ticket_pub_hex")
    pt.add_argument("ticket_key_id_hex")
    pt.add_argument("site_name")

    ps = sub.add_parser("stream")
    ps.add_argument("host")
    ps.add_argument("port", type=int)
    ps.add_argument("server_pub_hex")
    ps.add_argument("data")

    args = parser.parse_args(argv)
    if args.cmd == "ticket":
        params = make_ticket_params(args.ticket_pub_hex, args.ticket_key_id_hex)
        cookie, cli_pub, nonce = make_ticket_cookie(args.site_name, params)
        q, b = make_ticket_query_and_body(params)
        print("cookie=", cookie)
        print("query=", q[:64], "..")
        print("body=", b[:64], "..")
        return 0
    if args.cmd == "stream":
        client_priv = X25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        server_pub = bytes.fromhex(args.server_pub_hex)
        resp = open_stream_tcp(
            args.host, args.port, client_priv, server_pub, 1, args.data.encode()
        )
        print("resp=", resp)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
