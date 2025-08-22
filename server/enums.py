from enum import Enum


class TransportType(Enum):
    TCP12 = "tcp12"


class Profile(Enum):
    MINIMAL = "MINIMAL"
    STANDARD = "STANDARD"
    EXTENDED = "EXTENDED"


