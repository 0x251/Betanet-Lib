import logging
import sys


class Color:
    RESET = "\x1b[0m"
    DIM = "\x1b[2m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"


class PrettyFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        level = record.levelname
        color = Color.BLUE
        if level == "WARNING":
            color = Color.YELLOW
        elif level == "ERROR" or level == "CRITICAL":
            color = Color.RED
        elif level == "INFO":
            color = Color.GREEN
        msg = super().format(record)
        return f"{color}{level:<8}{Color.RESET} {record.name}: {msg}"


def setup(level: str = "INFO") -> None:
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    h = logging.StreamHandler(sys.stdout)
    fmt = PrettyFormatter("%(message)s")
    h.setFormatter(fmt)
    logger.handlers = [h]


