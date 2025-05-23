"""SCP prevents common admin role changes check."""

from kite.checks.scp_prevents_common_admin_role_changes.check import (
    check_scp_prevents_common_admin_role_changes,
)

__all__ = ["check_scp_prevents_common_admin_role_changes"]
