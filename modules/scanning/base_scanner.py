# modules/scanning/base_scanner.py

import logging
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    def __init__(self, domain_name: str, domain_id: int, conn):
        self.domain_name = domain_name
        self.domain_id = domain_id
        self.conn = conn
        self.cursor = conn.cursor()

    @abstractmethod
    def scan(self):
        """Perform the scanning task."""
        pass

    def log_error(self, message: str):
        """Log an error message."""
        logging.error(f"{self.domain_name}: {message}")

    def log_info(self, message: str):
        """Log an info message."""
        logging.info(f"{self.domain_name}: {message}")
