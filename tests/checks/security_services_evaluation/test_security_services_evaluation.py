"""Tests for the Security Services Evaluation check."""

from unittest.mock import patch

from kite.checks.security_services_evaluation.check import (
    check_security_services_evaluation,
)


@patch("kite.checks.security_services_evaluation.check.manual_check")
def test_security_services_evaluation_pass(mock_manual_check):
    """Test the check when teams evaluate and implement security services regularly."""
    mock_manual_check.return_value = {
        "check_id": "security-services-evaluation",
        "check_name": "Security Services Evaluation",
        "status": "PASS",
        "details": {
            "message": (
                "Teams regularly evaluate and implement new security services and "
                "features."
            )
        },
    }

    result = check_security_services_evaluation()

    assert result["check_id"] == "security-services-evaluation"
    assert result["check_name"] == "Security Services Evaluation"
    assert result["status"] == "PASS"
    assert (
        "Teams regularly evaluate and implement new security services"
        in result["details"]["message"]
    )


@patch("kite.checks.security_services_evaluation.check.manual_check")
def test_security_services_evaluation_fail(mock_manual_check):
    """Test the check when teams do not evaluate and implement security services regularly."""  # noqa: E501
    mock_manual_check.return_value = {
        "check_id": "security-services-evaluation",
        "check_name": "Security Services Evaluation",
        "status": "FAIL",
        "details": {
            "message": (
                "Teams should regularly evaluate and implement new security services "
                "and features."
            )
        },
    }

    result = check_security_services_evaluation()

    assert result["check_id"] == "security-services-evaluation"
    assert result["check_name"] == "Security Services Evaluation"
    assert result["status"] == "FAIL"
    assert (
        "Teams should regularly evaluate and implement new security services"
        in result["details"]["message"]
    )
