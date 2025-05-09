"""Tests for the Account Standards check."""

from unittest.mock import patch

from kite.checks.account_standards.check import check_account_standards


def test_account_standards_pass():
    """Test the check when new accounts are vended with suitable standards."""
    with patch(
        "kite.checks.account_standards.check.manual_check",
        return_value={
            "check_id": "account-standards",
            "check_name": "Account Standards",
            "status": "PASS",
            "details": {
                "message": (
                    "New accounts are vended with suitable standards already defined."
                ),
            },
        },
    ):
        result = check_account_standards()

    assert result["check_id"] == "account-standards"
    assert result["check_name"] == "Account Standards"
    assert result["status"] == "PASS"
    assert (
        "New accounts are vended with suitable standards already defined"
        in result["details"]["message"]
    )


def test_account_standards_fail():
    """Test the check when new accounts are not vended with suitable standards."""
    with patch(
        "kite.checks.account_standards.check.manual_check",
        return_value={
            "check_id": "account-standards",
            "check_name": "Account Standards",
            "status": "FAIL",
            "details": {
                "message": (
                    "New accounts should be vended with suitable standards already "
                    "defined."
                ),
            },
        },
    ):
        result = check_account_standards()

    assert result["check_id"] == "account-standards"
    assert result["check_name"] == "Account Standards"
    assert result["status"] == "FAIL"
    assert (
        "New accounts should be vended with suitable standards already defined"
        in result["details"]["message"]
    )
