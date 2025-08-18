from enum import Enum


class TicketCarrier(Enum):
    COOKIE = "cookie"
    QUERY = "query"
    BODY = "body"


class HttpMethod(Enum):
    GET = "GET"
    POST = "POST"


