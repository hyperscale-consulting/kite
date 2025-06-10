"""Check for service encryption at rest."""

from kite.checks.use_service_encryption_at_rest.check import (
    check_use_service_encryption_at_rest,
)

__all__ = ["check_use_service_encryption_at_rest"]
