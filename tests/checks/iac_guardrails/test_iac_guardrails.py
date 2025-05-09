"""Tests for the IaC Guardrails check."""

from unittest.mock import patch

from kite.checks.iac_guardrails.check import check_iac_guardrails


def test_iac_guardrails_pass():
    """Test the check when guardrails are in place."""
    with patch(
        "kite.checks.iac_guardrails.check.manual_check",
        return_value={
            "check_id": "iac-guardrails",
            "check_name": "IaC Guardrails",
            "status": "PASS",
            "details": {
                "message": (
                    "Guardrails are in place to detect and alert on misconfigurations "
                    "in templates before deployment."
                ),
            },
        },
    ):
        result = check_iac_guardrails()

    assert result["check_id"] == "iac-guardrails"
    assert result["check_name"] == "IaC Guardrails"
    assert result["status"] == "PASS"
    assert (
        "Guardrails are in place to detect and alert on misconfigurations"
        in result["details"]["message"]
    )


def test_iac_guardrails_fail():
    """Test the check when guardrails are not in place."""
    with patch(
        "kite.checks.iac_guardrails.check.manual_check",
        return_value={
            "check_id": "iac-guardrails",
            "check_name": "IaC Guardrails",
            "status": "FAIL",
            "details": {
                "message": (
                    "Guardrails should be in place to detect and alert on "
                    "misconfigurations in templates before deployment."
                ),
            },
        },
    ):
        result = check_iac_guardrails()

    assert result["check_id"] == "iac-guardrails"
    assert result["check_name"] == "IaC Guardrails"
    assert result["status"] == "FAIL"
    assert (
        "Guardrails should be in place to detect and alert on misconfigurations"
        in result["details"]["message"]
    )
