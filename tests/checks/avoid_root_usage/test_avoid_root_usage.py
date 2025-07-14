"""Tests for the avoid_root_usage check."""

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from unittest.mock import patch

import pytest

from kite.checks.avoid_root_usage.check import check_root_user_usage


@pytest.fixture
def mock_get_account_ids():
    """Mock the get_account_ids_in_scope function."""
    with patch("kite.checks.avoid_root_usage.check.get_account_ids_in_scope") as mock:
        mock.return_value = ["123456789012"]
        yield mock


@pytest.fixture
def mock_get_credentials_report():
    """Mock the get_credentials_report function."""
    with patch("kite.checks.avoid_root_usage.check.get_credentials_report") as mock:
        yield mock


def test_root_password_used_recently(mock_get_account_ids, mock_get_credentials_report):
    """Test when root password was used recently."""
    # Set up mock credentials report with recent password usage
    now = datetime.now(timezone.utc)
    recent_date = (now - timedelta(days=30)).isoformat()

    mock_get_credentials_report.return_value = {
        "root": {"password_last_used": recent_date}
    }

    result = check_root_user_usage()

    assert result["status"] == "FAIL"
    assert (
        "Root account password has been used in the last 90 days"
        in result["details"]["message"]
    )
    assert len(result["details"]["accounts_with_root_usage"]) == 1
    assert (
        result["details"]["accounts_with_root_usage"][0]["account_id"] == "123456789012"
    )


def test_root_password_not_used_recently(
    mock_get_account_ids, mock_get_credentials_report
):
    """Test when root password was not used recently."""
    # Set up mock credentials report with old password usage
    now = datetime.now(timezone.utc)
    old_date = (now - timedelta(days=100)).isoformat()

    mock_get_credentials_report.return_value = {
        "root": {"password_last_used": old_date}
    }

    result = check_root_user_usage()

    assert result["status"] == "PASS"
    assert (
        "Root account password has not been used in the last 90 days"
        in result["details"]["message"]
    )


def test_root_password_never_used(mock_get_account_ids, mock_get_credentials_report):
    """Test when root password has never been used."""
    mock_get_credentials_report.return_value = {"root": {"password_last_used": "N/A"}}

    result = check_root_user_usage()

    assert result["status"] == "PASS"
    assert (
        "Root account password has not been used in the last 90 days"
        in result["details"]["message"]
    )


def test_no_root_account(mock_get_account_ids, mock_get_credentials_report):
    """Test when there is no root account in the credentials report."""
    mock_get_credentials_report.return_value = {
        "user1": {"password_last_used": "2024-01-01T00:00:00Z"}
    }

    result = check_root_user_usage()

    assert result["status"] == "PASS"
    assert (
        "Root account password has not been used in the last 90 days"
        in result["details"]["message"]
    )


def test_error_getting_credentials_report(
    mock_get_account_ids, mock_get_credentials_report
):
    """Test error handling when getting credentials report fails."""
    # Set up mock to raise an exception for the first account
    mock_get_credentials_report.side_effect = Exception(
        "Failed to get credentials report"
    )

    # Set up mock to return a valid report for the second account
    def mock_credentials_report(account_id):
        if account_id == "123456789012":
            raise Exception("Failed to get credentials report")
        return {"root": {"password_last_used": "N/A"}}

    # Set up mock to return multiple account IDs
    mock_get_account_ids.return_value = ["123456789012", "987654321098"]
    mock_get_credentials_report.side_effect = mock_credentials_report

    result = check_root_user_usage()

    # The function should handle the exception gracefully and return PASS
    assert result["status"] == "PASS"
    assert (
        "Root account password has not been used in the last 90 days"
        in result["details"]["message"]
    )


def test_multiple_accounts_with_root_usage(
    mock_get_account_ids, mock_get_credentials_report
):
    """Test when multiple accounts have root password usage."""
    # Set up mock to return different account IDs
    mock_get_account_ids.return_value = ["111111111111", "222222222222"]

    # Set up mock to return different credentials reports for each account
    now = datetime.now(timezone.utc)
    recent_date = (now - timedelta(days=30)).isoformat()

    def mock_credentials_report(account_id):
        return {"root": {"password_last_used": recent_date}}

    mock_get_credentials_report.side_effect = mock_credentials_report

    result = check_root_user_usage()

    assert result["status"] == "FAIL"
    assert (
        "Root account password has been used in the last 90 days"
        in result["details"]["message"]
    )
    assert len(result["details"]["accounts_with_root_usage"]) == 2
    account_ids = {
        acc["account_id"] for acc in result["details"]["accounts_with_root_usage"]
    }
    assert account_ids == {"111111111111", "222222222222"}
