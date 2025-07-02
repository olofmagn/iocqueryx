import logging

"""
Logging functionality
"""

class LoggingManager:
    """
    Initialize the logger instance

    Returns:
    - The logger associated with this module
    """
    def __init__(self, name: str ="IocQueryx", level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        if not self.logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def get_logger(self) -> logging.Logger:
        return self.logger
