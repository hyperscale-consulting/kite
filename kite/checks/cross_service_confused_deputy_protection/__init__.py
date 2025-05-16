"""Cross-service confused deputy protection check module."""

from kite.checks.cross_service_confused_deputy_protection.check import (
    check_cross_service_confused_deputy_protection,
    CHECK_ID,
    CHECK_NAME,
)

__all__ = ["check_cross_service_confused_deputy_protection", "CHECK_ID", "CHECK_NAME"]
