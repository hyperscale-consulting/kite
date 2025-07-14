"""Tests for the Security Risks check."""

from unittest.mock import patch

from kite.checks.security_risks.check import check_security_risks


@patch("kite.checks.security_risks.check.manual_check")
def test_security_risks_pass(mock_manual_check):
    """Test the Security Risks check when teams have identified and addressed risks."""
    mock_manual_check.return_value = {
        "check_id": "security-risks",
        "check_name": "Security Risks",
        "status": "PASS",
        "details": {
            "message": (
                "Teams have done a good job at identifying and addressing "
                "security risks."
            )
        },
    }

    result = check_security_risks()

    assert result["check_id"] == "security-risks"
    assert result["check_name"] == "Security Risks"
    assert result["status"] == "PASS"
    assert "Teams have done a good job" in result["details"]["message"]


@patch("kite.checks.security_risks.check.manual_check")
def test_security_risks_fail(mock_manual_check):
    """Test the Security Risks check when teams have not identified and addressed risks."""  # noqa: E501
    mock_manual_check.return_value = {
        "check_id": "security-risks",
        "check_name": "Security Risks",
        "status": "FAIL",
        "details": {
            "message": (
                "Teams should do a better job at identifying and addressing "
                "security risks."
            )
        },
    }

    result = check_security_risks()

    assert result["check_id"] == "security-risks"
    assert result["check_name"] == "Security Risks"
    assert result["status"] == "FAIL"
    assert "Teams should do a better job" in result["details"]["message"]
