import logging
import sys

SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

class ColorFormatter(logging.Formatter):
    BLUE = "\033[34m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    RESET = "\033[0m"

    COLORS = {
        logging.DEBUG: BLUE,
        logging.INFO: GREEN,
        SUCCESS_LEVEL: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.RESET)
        
        format_str = f"%(asctime)s - {color}%(levelname)s{self.RESET} - %(message)s"
        
        formatter = logging.Formatter(format_str, datefmt="%H:%M:%S")
        return formatter.format(record)


class AppLogger:
    def __init__(self):
        self._logger = logging.getLogger("clean_logger")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        
        if not self._logger.hasHandlers():
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(ColorFormatter())
            self._logger.addHandler(console_handler)

    def debug(self, message: str) -> None:
        self._logger.debug(message)

    def info(self, message: str) -> None:
        self._logger.info(message)

    def success(self, message: str) -> None:
        self._logger.log(SUCCESS_LEVEL, message)

    def warn(self, message: str) -> None:
        self._logger.warning(message)

    def error(self, message: str) -> None:
        self._logger.error(message)

logger = AppLogger()