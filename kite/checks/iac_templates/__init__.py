"""IaC templates check."""

from kite.checks.iac_templates.check import check_iac_templates
from kite.checks.iac_templates.check import CHECK_ID
from kite.checks.iac_templates.check import CHECK_NAME

__all__ = ["check_iac_templates", "CHECK_ID", "CHECK_NAME"]
