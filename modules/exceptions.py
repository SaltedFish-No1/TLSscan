# modules/exceptions.py

class ScannerError(Exception):
    """Base class for scanner exceptions."""
    pass

class ConnectionError(ScannerError):
    """Raised when there is a connection error."""
    pass

class SSLHandshakeError(ScannerError):
    """Raised when SSL handshake fails."""
    pass

# Add more custom exceptions as needed
