"""S3 confused deputy protection check package."""

from .check import (
    check_s3_confused_deputy_protection,
    CHECK_ID,
    CHECK_NAME,
)

__all__ = [
    "check_s3_confused_deputy_protection",
    "CHECK_ID",
    "CHECK_NAME",
]
