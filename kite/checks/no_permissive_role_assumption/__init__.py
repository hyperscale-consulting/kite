"""No permissive role assumption check module."""

from kite.checks.no_permissive_role_assumption.check import CHECK_ID
from kite.checks.no_permissive_role_assumption.check import CHECK_NAME
from kite.checks.no_permissive_role_assumption.check import (
    check_no_permissive_role_assumption,
)

__all__ = ["check_no_permissive_role_assumption", "CHECK_ID", "CHECK_NAME"]
