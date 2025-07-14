"""IaC version control check."""

from kite.checks.iac_version_control.check import check_iac_version_control
from kite.checks.iac_version_control.check import CHECK_ID
from kite.checks.iac_version_control.check import CHECK_NAME

__all__ = ["check_iac_version_control", "CHECK_ID", "CHECK_NAME"]
