"""Expose the check_automate_s3_data_retention function."""

from kite.checks.automate_s3_data_retention.check import (
    check_automate_s3_data_retention,
)

__all__ = ["check_automate_s3_data_retention"]
