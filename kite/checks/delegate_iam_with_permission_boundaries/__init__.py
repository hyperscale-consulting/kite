"""Delegate IAM with permission boundaries check module."""

from .check import (
    CHECK_ID,
    CHECK_NAME,
    check_delegate_iam_with_permission_boundaries,
)

__all__ = [
    "CHECK_ID",
    "CHECK_NAME",
    "check_delegate_iam_with_permission_boundaries",
]
