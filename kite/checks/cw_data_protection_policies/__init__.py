"""CloudWatch data protection policies check."""

from kite.checks.cw_data_protection_policies.check import (
    check_cw_data_protection_policies,
)

__all__ = ["check_cw_data_protection_policies"]
