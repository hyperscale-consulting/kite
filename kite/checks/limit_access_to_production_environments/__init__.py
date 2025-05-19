"""Check for limiting access to production environments."""

from kite.checks.limit_access_to_production_environments.check import (
    check_limit_access_to_production_environments,
)

__all__ = ["check_limit_access_to_production_environments"]
