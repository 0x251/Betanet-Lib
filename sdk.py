from typing import Tuple

from betanet.tickets import (
    TicketPolicy,
    TicketParams,
    generate_client_cookie,
    generate_client_payload,
    encode_query,
    encode_form_body,
)
from betanet.transport.tcp import HtxTcpClient
from betanet.gateway.enums import TicketCarrier


def make_ticket_params(
    ticket_pub_hex: str, ticket_key_id_hex: str, min_len: int = 24, max_len: int = 64
) -> TicketParams:
    ticket_pub = bytes.fromhex(ticket_pub_hex)
    ticket_key_id = bytes.fromhex(ticket_key_id_hex)
    policy = TicketPolicy(
        carriers={TicketCarrier.COOKIE.value: 1.0, TicketCarrier.QUERY.value: 0.0, TicketCarrier.BODY.value: 0.0},
        min_len=min_len,
        max_len=max_len,
    )
    return TicketParams(
        ticket_pub=ticket_pub, ticket_key_id=ticket_key_id, policy=policy
    )


def make_ticket_cookie(
    site_name: str, params: TicketParams
) -> Tuple[str, bytes, bytes]:
    return generate_client_cookie(site_name, params)


def make_ticket_query_and_body(params: TicketParams) -> Tuple[str, bytes]:
    payload, cli_pub, nonce = generate_client_payload(params)
    return encode_query(payload), encode_form_body(payload)


def open_stream_tcp(
    host: str,
    port: int,
    client_priv: bytes,
    server_pub: bytes,
    stream_id: int = 1,
    payload: bytes = b"",
) -> bytes:
    cli = HtxTcpClient(host, port, client_priv, server_pub)
    return cli.roundtrip(stream_id, payload)
