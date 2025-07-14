"""Credential rotation check."""

from kite.checks.credential_rotation.check import check_credential_rotation
from kite.checks.credential_rotation.check import CHECK_ID
from kite.checks.credential_rotation.check import CHECK_NAME

__all__ = ["check_credential_rotation", "CHECK_ID", "CHECK_NAME"]
