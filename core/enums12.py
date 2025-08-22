from enum import IntEnum


class FrameType12(IntEnum):
    STREAM = 0
    WINDOW_UPDATE = 1
    PING = 2
    KEY_UPDATE = 3
    CLOSE = 4


