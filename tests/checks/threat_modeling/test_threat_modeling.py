"""Tests for the Threat Modeling check."""

from unittest.mock import patch

from kite.checks.threat_modeling.check import check_threat_modeling


def test_threat_modeling_pass():
    """Test the check when teams perform threat modeling regularly."""
    with patch(
        "kite.checks.threat_modeling.check.manual_check",
        return_value={
            "check_id": "threat-modeling",
            "check_name": "Threat Modeling",
            "status": "PASS",
            "details": {
                "message": "Teams perform threat modeling regularly.",
            },
        },
    ):
        result = check_threat_modeling()

    assert result["check_id"] == "threat-modeling"
    assert result["check_name"] == "Threat Modeling"
    assert result["status"] == "PASS"
    assert (
        "Teams perform threat modeling regularly"
        in result["details"]["message"]
    )


def test_threat_modeling_fail():
    """Test the check when teams do not perform threat modeling regularly."""
    with patch(
        "kite.checks.threat_modeling.check.manual_check",
        return_value={
            "check_id": "threat-modeling",
            "check_name": "Threat Modeling",
            "status": "FAIL",
            "details": {
                "message": "Teams should perform threat modeling regularly.",
            },
        },
    ):
        result = check_threat_modeling()

    assert result["check_id"] == "threat-modeling"
    assert result["check_name"] == "Threat Modeling"
    assert result["status"] == "FAIL"
    assert (
        "Teams should perform threat modeling regularly"
        in result["details"]["message"]
    )
