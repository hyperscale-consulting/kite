"""Tests for the IaC Version Control check."""

from unittest.mock import patch

from kite.checks.iac_version_control.check import check_iac_version_control


def test_iac_version_control_pass():
    """Test the check when IaC templates are stored in version control."""
    with patch(
        "kite.checks.iac_version_control.check.manual_check",
        return_value={
            "check_id": "iac-version-control",
            "check_name": "IaC Version Control",
            "status": "PASS",
            "details": {
                "message": (
                    "IaC templates are stored in version control, tested as part of a "
                    "CI/CD pipeline and automatically deployed to production."
                ),
            },
        },
    ):
        result = check_iac_version_control()

    assert result["check_id"] == "iac-version-control"
    assert result["check_name"] == "IaC Version Control"
    assert result["status"] == "PASS"
    assert (
        "IaC templates are stored in version control, tested as part of a CI/CD"
        in result["details"]["message"]
    )


def test_iac_version_control_fail():
    """Test the check when IaC templates are not stored in version control."""
    with patch(
        "kite.checks.iac_version_control.check.manual_check",
        return_value={
            "check_id": "iac-version-control",
            "check_name": "IaC Version Control",
            "status": "FAIL",
            "details": {
                "message": (
                    "IaC templates should be stored in version control, tested as part "
                    "of a CI/CD pipeline and automatically deployed to production."
                ),
            },
        },
    ):
        result = check_iac_version_control()

    assert result["check_id"] == "iac-version-control"
    assert result["check_name"] == "IaC Version Control"
    assert result["status"] == "FAIL"
    assert (
        "IaC templates should be stored in version control, tested as part of a CI/CD"
        in result["details"]["message"]
    )
