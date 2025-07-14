"""SNS confused deputy protection check package."""

from kite.checks.sns_confused_deputy_protection.check import CHECK_ID
from kite.checks.sns_confused_deputy_protection.check import CHECK_NAME
from kite.checks.sns_confused_deputy_protection.check import (
    check_sns_confused_deputy_protection,
)

__all__ = [
    "check_sns_confused_deputy_protection",
    "CHECK_ID",
    "CHECK_NAME",
]
