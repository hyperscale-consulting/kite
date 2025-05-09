"""Tests for the IaC Templates check."""

from unittest.mock import patch

from kite.checks.iac_templates.check import check_iac_templates


def test_iac_templates_pass():
    """Test the check when IaC templates are used."""
    with patch(
        "kite.checks.iac_templates.check.manual_check",
        return_value={
            "check_id": "iac-templates",
            "check_name": "IaC Templates",
            "status": "PASS",
            "details": {
                "message": (
                    "Standard security controls and configurations are defined using "
                    "Infrastructure as Code (IaC) templates."
                ),
            },
        },
    ):
        result = check_iac_templates()

    assert result["check_id"] == "iac-templates"
    assert result["check_name"] == "IaC Templates"
    assert result["status"] == "PASS"
    assert (
        "Standard security controls and configurations are defined using"
        in result["details"]["message"]
    )


def test_iac_templates_fail():
    """Test the check when IaC templates are not used."""
    with patch(
        "kite.checks.iac_templates.check.manual_check",
        return_value={
            "check_id": "iac-templates",
            "check_name": "IaC Templates",
            "status": "FAIL",
            "details": {
                "message": (
                    "Standard security controls and configurations should be defined "
                    "using Infrastructure as Code (IaC) templates."
                ),
            },
        },
    ):
        result = check_iac_templates()

    assert result["check_id"] == "iac-templates"
    assert result["check_name"] == "IaC Templates"
    assert result["status"] == "FAIL"
    assert (
        "Standard security controls and configurations should be defined using"
        in result["details"]["message"]
    )
