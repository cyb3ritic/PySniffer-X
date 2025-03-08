class SnifferError(Exception):
    """Base exception for sniffer-related errors"""
    pass

class InvalidInterfaceError(SnifferError):
    """Raised when an invalid network interface is specified"""
    pass

class CaptureError(SnifferError):
    """Raised when packet capture fails"""
    pass