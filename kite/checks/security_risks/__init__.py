"""Security Risks check."""

from kite.checks.security_risks.check import CHECK_ID
from kite.checks.security_risks.check import CHECK_NAME
from kite.checks.security_risks.check import check_security_risks

__all__ = ["check_security_risks", "CHECK_ID", "CHECK_NAME"]
