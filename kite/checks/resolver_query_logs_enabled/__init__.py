"""Route 53 Resolver query logs enabled check module."""

from kite.checks.resolver_query_logs_enabled.check import (
    check_resolver_query_logs_enabled,
)

__all__ = ["check_resolver_query_logs_enabled"]
