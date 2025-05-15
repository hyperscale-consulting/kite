"""No IAM policy allows privilege escalation check module."""

from kite.checks.no_policy_allows_privilege_escalation.check import (
    check_no_policy_allows_privilege_escalation,
    CHECK_ID,
    CHECK_NAME,
)

__all__ = ["check_no_policy_allows_privilege_escalation", "CHECK_ID", "CHECK_NAME"]
