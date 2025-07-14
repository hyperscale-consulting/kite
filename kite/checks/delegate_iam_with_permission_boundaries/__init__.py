"""Delegate IAM with permission boundaries check module."""

from .check import check_delegate_iam_with_permission_boundaries
from .check import CHECK_ID
from .check import CHECK_NAME

__all__ = [
    "CHECK_ID",
    "CHECK_NAME",
    "check_delegate_iam_with_permission_boundaries",
]
