"""S3 confused deputy protection check package."""

from .check import CHECK_ID
from .check import CHECK_NAME
from .check import check_s3_confused_deputy_protection

__all__ = [
    "check_s3_confused_deputy_protection",
    "CHECK_ID",
    "CHECK_NAME",
]
