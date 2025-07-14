"""Use centralized identity provider check."""

from kite.checks.use_centralized_idp.check import CHECK_ID
from kite.checks.use_centralized_idp.check import CHECK_NAME
from kite.checks.use_centralized_idp.check import check_use_centralized_idp

__all__ = ["check_use_centralized_idp", "CHECK_ID", "CHECK_NAME"]
