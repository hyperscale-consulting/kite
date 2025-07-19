from unittest.mock import patch

import pytest

from kite.checks.no_root_access_keys import check_no_root_access_keys


@pytest.fixture
def mock_get_account_ids():
    """Mock the get_account_ids_in_scope function."""
    with patch("kite.checks.no_root_access_keys.get_account_ids_in_scope") as mock:
        mock.return_value = ["123456789012", "098765432109"]
        yield mock


@pytest.fixture
def mock_get_account_summary():
    """Mock the get_account_summary function."""
    with patch("kite.checks.no_root_access_keys.get_account_summary") as mock:
        yield mock


def test_check_no_root_access_keys_pass(mock_get_account_ids, mock_get_account_summary):
    """Test the check when no root access keys are found."""
    # Set up mock account summaries with no root access keys
    mock_get_account_summary.side_effect = [
        {"AccountAccessKeysPresent": 0},
        {"AccountAccessKeysPresent": 0},
    ]

    result = check_no_root_access_keys()

    # Verify the result
    assert result["check_id"] == "no-root-access-keys"
    assert result["check_name"] == "No Root Access Keys"
    assert result["status"] == "PASS"
    assert "No root access keys found in any accounts" in result["details"]["message"]
    assert result["details"]["accounts_with_root_keys"] == []


def test_check_no_root_access_keys_fail(mock_get_account_ids, mock_get_account_summary):
    """Test the check when root access keys are found."""
    # Set up mock account summaries with one account having root access keys
    mock_get_account_summary.side_effect = [
        {"AccountAccessKeysPresent": 1},
        {"AccountAccessKeysPresent": 0},
    ]

    result = check_no_root_access_keys()

    # Verify the result
    assert result["check_id"] == "no-root-access-keys"
    assert result["check_name"] == "No Root Access Keys"
    assert result["status"] == "FAIL"
    assert "Root access keys found in 1 accounts" in result["details"]["message"]
    assert result["details"]["accounts_with_root_keys"] == ["123456789012"]


def test_check_no_root_access_keys_error(
    mock_get_account_ids, mock_get_account_summary
):
    """Test the check when an error occurs."""
    # Set up mock to raise an exception
    mock_get_account_summary.side_effect = Exception("Test error")

    result = check_no_root_access_keys()

    # Verify the result
    assert result["check_id"] == "no-root-access-keys"
    assert result["check_name"] == "No Root Access Keys"
    assert result["status"] == "ERROR"
    assert (
        "Error checking for root access keys: Test error"
        in result["details"]["message"]
    )


def test_check_no_root_access_keys_no_accounts(
    mock_get_account_ids, mock_get_account_summary
):
    """Test when there are no accounts in scope."""
    # Set up mock to return no accounts
    mock_get_account_ids.return_value = []

    result = check_no_root_access_keys()

    # Verify the result
    assert result["check_id"] == "no-root-access-keys"
    assert result["check_name"] == "No Root Access Keys"
    assert result["status"] == "PASS"
    assert "No root access keys found in any accounts" in result["details"]["message"]
    assert result["details"]["accounts_with_root_keys"] == []
