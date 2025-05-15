"""No full admin policies check module."""

from kite.checks.no_full_admin_policies.check import (
    check_no_full_admin_policies,
    CHECK_ID,
    CHECK_NAME,
)

__all__ = ["check_no_full_admin_policies", "CHECK_ID", "CHECK_NAME"]
