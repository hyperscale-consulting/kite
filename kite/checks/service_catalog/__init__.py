"""Service Catalog check."""

from kite.checks.service_catalog.check import CHECK_ID
from kite.checks.service_catalog.check import CHECK_NAME
from kite.checks.service_catalog.check import check_service_catalog

__all__ = ["check_service_catalog", "CHECK_ID", "CHECK_NAME"]
