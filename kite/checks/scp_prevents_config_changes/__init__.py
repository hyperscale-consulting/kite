"""SCP prevents AWS Config changes check."""

from .check import check_scp_prevents_config_changes

__all__ = ["check_scp_prevents_config_changes"]
