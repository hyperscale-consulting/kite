"""AWS control documentation check."""

from kite.checks.aws_control_documentation.check import (
    check_aws_control_documentation,
    CHECK_ID,
    CHECK_NAME,
)

__all__ = ["check_aws_control_documentation", "CHECK_ID", "CHECK_NAME"]
