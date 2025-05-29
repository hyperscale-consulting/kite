"""WAF Web ACL logging check."""

from kite.checks.waf_web_acl_logging_enabled.check import (
    check_waf_web_acl_logging_enabled,
)

__all__ = ["check_waf_web_acl_logging_enabled"]
