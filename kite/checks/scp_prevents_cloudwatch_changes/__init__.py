"""SCP prevents CloudWatch changes check."""

from kite.checks.scp_prevents_cloudwatch_changes.check import (
    check_scp_prevents_cloudwatch_changes,
)

__all__ = ["check_scp_prevents_cloudwatch_changes"]
