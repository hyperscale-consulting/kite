"""Tests for threat intelligence monitoring check."""

import pytest
from unittest.mock import patch

from kite.checks.threat_intelligence_monitoring.check import (
    check_threat_intelligence_monitoring,
)


def test_check_threat_intelligence_monitoring_pass():
    """Test successful threat intelligence monitoring check."""
    patch_path = "kite.checks.threat_intelligence_monitoring.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.return_value = {
            "status": "PASS",
            "details": {
                "message": "Teams have established reliable and repeatable mechanisms"
            }
        }
        result = check_threat_intelligence_monitoring()
        assert result["status"] == "PASS"
        assert (
            "Teams have established reliable and repeatable mechanisms"
            in result["details"]["message"]
        )


def test_check_threat_intelligence_monitoring_fail():
    """Test failed threat intelligence monitoring check."""
    patch_path = "kite.checks.threat_intelligence_monitoring.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.return_value = {
            "status": "FAIL",
            "details": {
                "message": "Teams lack reliable and repeatable mechanisms"
            }
        }
        result = check_threat_intelligence_monitoring()
        assert result["status"] == "FAIL"
        assert (
            "Teams lack reliable and repeatable mechanisms"
            in result["details"]["message"]
        )


def test_check_threat_intelligence_monitoring_error():
    """Test error handling in threat intelligence monitoring check."""
    patch_path = "kite.checks.threat_intelligence_monitoring.check.manual_check"
    with patch(patch_path) as mock_check:
        mock_check.side_effect = Exception("Test error")
        with pytest.raises(Exception):
            check_threat_intelligence_monitoring()
