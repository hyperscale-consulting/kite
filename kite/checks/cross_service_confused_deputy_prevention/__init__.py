"""Cross-service confused deputy prevention check."""

from .check import (
    check_cross_service_confused_deputy_prevention,
    CHECK_ID,
    CHECK_NAME,
)

__all__ = [
    "check_cross_service_confused_deputy_prevention",
    "CHECK_ID",
    "CHECK_NAME",
]
