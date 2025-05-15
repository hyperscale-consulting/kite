"""No full access to sensitive services check module."""

from kite.checks.no_full_access_to_sensitive_services.check import (
    check_no_full_access_to_sensitive_services,
    CHECK_ID,
    CHECK_NAME,
)

__all__ = ["check_no_full_access_to_sensitive_services", "CHECK_ID", "CHECK_NAME"]
