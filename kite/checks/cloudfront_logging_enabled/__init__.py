"""CloudFront logging check."""

from kite.checks.cloudfront_logging_enabled.check import (
    check_cloudfront_logging_enabled,
)

__all__ = ["check_cloudfront_logging_enabled"]
