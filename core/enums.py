from enum import IntEnum


class FrameType(IntEnum):
    STREAM = 0
    PING = 1
    CLOSE = 2
    KEY_UPDATE = 3
    WINDOW_UPDATE = 4


