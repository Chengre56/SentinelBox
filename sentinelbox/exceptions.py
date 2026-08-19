from typing import Optional


class SentinelBoxError(Exception):
    """Base exception for all SentinelBox errors."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class SandboxCreationError(SentinelBoxError):
    """Raised when sandbox workspace initialization fails."""
    pass


class GuardViolation(SentinelBoxError):
    """Raised when a command violates security policy."""
    pass


class CommandExecutionError(SentinelBoxError):
    """Raised when execution fails in an unexpected manner."""
    pass


class CommandTimeout(SentinelBoxError):
    """Raised when a command exceeds its allotted timeout."""
    pass


class VerificationError(SentinelBoxError):
    """Raised when verification pipeline validation fails."""
    pass


class CommitError(SentinelBoxError):
    """Raised when an atomic commit operation fails."""
    pass


class RollbackError(SentinelBoxError):
    """Raised when rollback operations fail."""
    pass


class SnapshotError(SentinelBoxError):
    """Raised when filesystem state capture or comparison fails."""
    pass


class PolicyError(SentinelBoxError):
    """Raised when policy specification is malformed or invalid."""
    pass


class TransactionConflict(SentinelBoxError):
    """Raised when live workspace state changed concurrently outside SentinelBox."""
    pass


class PathSecurityError(SentinelBoxError):
    """Raised when a path traversal, symlink escape, or illegal path is detected."""
    pass


class ResourceLimitExceeded(SentinelBoxError):
    """Raised when execution limits (memory, output, disk) are violated."""
    pass