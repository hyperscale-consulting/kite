"""SCP prevents deleting logs check module."""

from kite.checks.scp_prevents_deleting_logs.check import (
    check_scp_prevents_deleting_logs,
)

__all__ = ["check_scp_prevents_deleting_logs"]
