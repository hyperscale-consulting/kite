"""Tests for the Accurate Account Contact Details check."""

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from kite.checks.accurate_account_contact_details.check import (
    check_accurate_account_contact_details,
)


@pytest.fixture
def mock_get_organization_features():
    """Mock the get_organization_features function."""
    with patch(
        "kite.checks.accurate_account_contact_details.check.get_organization_features"
    ) as mock:
        yield mock


@pytest.fixture
def mock_config():
    """Mock the Config.get function."""
    with patch("kite.checks.accurate_account_contact_details.check.Config.get") as mock:
        yield mock


@pytest.fixture
def mock_get_account_ids():
    """Mock the get_account_ids_in_scope function."""
    with patch(
        "kite.checks.accurate_account_contact_details.check.get_account_ids_in_scope"
    ) as mock:
        mock.return_value = ["123456789012", "098765432109"]
        yield mock


@pytest.fixture
def mock_manual_check():
    """Mock the manual_check function."""
    with patch(
        "kite.checks.accurate_account_contact_details.check.manual_check"
    ) as mock:
        yield mock


def test_acc_contact_details_org_managed_pass(
    mock_get_organization_features,
    mock_config,
    mock_manual_check,
):
    """Test when root credentials are managed at org level.

    Verifies behavior when contact details are accurate.
    """
    # Set up mocks
    mock_get_organization_features.return_value = ["RootCredentialsManagement"]
    mock_config.return_value = MagicMock(management_account_id="123456789012")
    mock_manual_check.return_value = {
        "check_id": "accurate-account-contact-details",
        "check_name": "Accurate Account Contact Details",
        "status": "PASS",
        "details": {
            "message": (
                "Contact details for the management account are accurate and secure."
            ),
        },
    }

    result = check_accurate_account_contact_details()

    # Verify the result
    assert result["check_id"] == "accurate-account-contact-details"
    assert result["check_name"] == "Accurate Account Contact Details"
    assert result["status"] == "PASS"
    expected_message = (
        "Contact details for the management account are accurate and secure."
    )
    assert expected_message in result["details"]["message"]


def test_acc_contact_details_org_managed_fail(
    mock_get_organization_features,
    mock_config,
    mock_manual_check,
):
    """Test when root credentials are managed at org level.

    Verifies behavior when contact details are not accurate.
    """
    # Set up mocks
    mock_get_organization_features.return_value = ["RootCredentialsManagement"]
    mock_config.return_value = MagicMock(management_account_id="123456789012")
    mock_manual_check.return_value = {
        "check_id": "accurate-account-contact-details",
        "check_name": "Accurate Account Contact Details",
        "status": "FAIL",
        "details": {
            "message": ("Contact details for the management account need improvement."),
        },
    }

    result = check_accurate_account_contact_details()

    # Verify the result
    assert result["check_id"] == "accurate-account-contact-details"
    assert result["check_name"] == "Accurate Account Contact Details"
    assert result["status"] == "FAIL"
    expected_message = "Contact details for the management account need improvement."
    assert expected_message in result["details"]["message"]


def test_acc_contact_details_org_managed_no_mgmt_account(
    mock_get_organization_features,
    mock_config,
):
    """Test when root credentials are managed at org level.

    Verifies behavior when management account ID cannot be determined.
    """
    # Set up mocks
    mock_get_organization_features.return_value = ["RootCredentialsManagement"]
    mock_config.return_value = MagicMock(management_account_id=None)

    result = check_accurate_account_contact_details()

    # Verify the result
    assert result["check_id"] == "accurate-account-contact-details"
    assert result["check_name"] == "Accurate Account Contact Details"
    assert result["status"] == "ERROR"
    error_message = (
        "Root credentials management is enabled, but management account ID "
        "could not be determined."
    )
    assert error_message in result["details"]["message"]


def test_acc_contact_details_not_org_managed_pass(
    mock_get_organization_features,
    mock_config,
    mock_get_account_ids,
    mock_manual_check,
):
    """Test when root credentials are not managed at org level.

    Verifies behavior when all account contact details are accurate.
    """
    # Set up mocks
    mock_get_organization_features.return_value = []
    mock_config.return_value = MagicMock(management_account_id="123456789012")
    mock_manual_check.return_value = {
        "check_id": "accurate-account-contact-details",
        "check_name": "Accurate Account Contact Details",
        "status": "PASS",
        "details": {
            "message": ("Contact details for all accounts are accurate and secure."),
        },
    }

    result = check_accurate_account_contact_details()

    # Verify the result
    assert result["check_id"] == "accurate-account-contact-details"
    assert result["check_name"] == "Accurate Account Contact Details"
    assert result["status"] == "PASS"
    expected_message = "Contact details for all accounts are accurate and secure."
    assert expected_message in result["details"]["message"]


def test_acc_contact_details_not_org_managed_fail(
    mock_get_organization_features,
    mock_config,
    mock_get_account_ids,
    mock_manual_check,
):
    """Test when root credentials are not managed at org level.

    Verifies behavior when account contact details are not accurate.
    """
    # Set up mocks
    mock_get_organization_features.return_value = []
    mock_config.return_value = MagicMock(management_account_id="123456789012")
    mock_manual_check.return_value = {
        "check_id": "accurate-account-contact-details",
        "check_name": "Accurate Account Contact Details",
        "status": "FAIL",
        "details": {
            "message": ("Contact details for some accounts need improvement."),
        },
    }

    result = check_accurate_account_contact_details()

    # Verify the result
    assert result["check_id"] == "accurate-account-contact-details"
    assert result["check_name"] == "Accurate Account Contact Details"
    assert result["status"] == "FAIL"
    expected_message = "Contact details for some accounts need improvement."
    assert expected_message in result["details"]["message"]


def test_acc_contact_details_error(
    mock_get_organization_features,
):
    """Test when an error occurs during the check."""
    # Set up mock to raise an exception
    mock_get_organization_features.side_effect = Exception("Test error")

    result = check_accurate_account_contact_details()

    # Verify the result
    assert result["check_id"] == "accurate-account-contact-details"
    assert result["check_name"] == "Accurate Account Contact Details"
    assert result["status"] == "ERROR"
    assert (
        "Error checking account contact details: Test error"
        in result["details"]["message"]
    )
