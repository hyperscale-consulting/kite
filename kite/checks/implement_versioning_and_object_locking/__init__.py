"""Check for S3 bucket versioning and object locking."""

from kite.checks.implement_versioning_and_object_locking.check import (
    check_implement_versioning_and_object_locking,
)

__all__ = ["check_implement_versioning_and_object_locking"]
