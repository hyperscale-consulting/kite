"""Expose the check_no_human_access_to_unencrypted_key_material function."""

from kite.checks.no_human_access_to_unencrypted_key_material.check import (
    check_no_human_access_to_unencrypted_key_material,
)

__all__ = ["check_no_human_access_to_unencrypted_key_material"]
