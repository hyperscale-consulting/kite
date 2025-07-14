"""Threat modeling check."""

from kite.checks.threat_modeling.check import CHECK_ID
from kite.checks.threat_modeling.check import CHECK_NAME
from kite.checks.threat_modeling.check import check_threat_modeling

__all__ = ["check_threat_modeling", "CHECK_ID", "CHECK_NAME"]
