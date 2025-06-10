"""Check for encryption at rest misconfigurations using AWS Config."""

from kite.checks.detect_encryption_at_rest_misconfig.check import (
    check_detect_encryption_at_rest_misconfig,
)

__all__ = ["check_detect_encryption_at_rest_misconfig"]
