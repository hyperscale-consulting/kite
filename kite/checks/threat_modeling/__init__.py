"""Threat modeling check."""

from kite.checks.threat_modeling.check import (
    check_threat_modeling,
    CHECK_ID,
    CHECK_NAME,
)

__all__ = ["check_threat_modeling", "CHECK_ID", "CHECK_NAME"]
