"""Grant least privilege access check module."""

from kite.checks.grant_least_privilege_access.check import (
    check_grant_least_privilege_access,
)
from kite.checks.grant_least_privilege_access.check import CHECK_ID
from kite.checks.grant_least_privilege_access.check import CHECK_NAME

__all__ = ["check_grant_least_privilege_access", "CHECK_ID", "CHECK_NAME"]
