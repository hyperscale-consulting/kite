"""Tests for the Root MFA Enabled check."""

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from kite.checks.root_mfa_enabled.check import check_root_mfa_enabled


@pytest.fixture
def mock_get_organization_features():
    """Mock the get_organization_features function."""
    with patch("kite.checks.root_mfa_enabled.check.get_organization_features") as mock:
        yield mock


@pytest.fixture
def mock_config():
    """Mock the Config.get function."""
    with patch("kite.checks.root_mfa_enabled.check.Config.get") as mock:
        yield mock


@pytest.fixture
def mock_get_account_ids():
    """Mock the get_account_ids_in_scope function."""
    with patch("kite.checks.root_mfa_enabled.check.get_account_ids_in_scope") as mock:
        mock.return_value = ["123456789012", "098765432109"]
        yield mock


@pytest.fixture
def mock_get_account_summary():
    """Mock the get_account_summary function."""
    with patch("kite.checks.root_mfa_enabled.check.get_account_summary") as mock:
        yield mock


@pytest.fixture
def mock_get_root_virtual_mfa_device():
    """Mock the get_root_virtual_mfa_device function."""
    with patch(
        "kite.checks.root_mfa_enabled.check.get_root_virtual_mfa_device"
    ) as mock:
        yield mock


def test_root_mfa_org_managed_pass(
    mock_get_organization_features,
    mock_config,
    mock_get_account_summary,
    mock_get_root_virtual_mfa_device,
):
    """Test when root credentials are managed at org level.

    Verifies behavior when MFA is enabled with hardware device.
    """
    # Set up mocks
    mock_get_organization_features.return_value = ["RootCredentialsManagement"]
    mock_config.return_value = MagicMock(management_account_id="123456789012")
    mock_get_account_summary.return_value = {"AccountMFAEnabled": 1}
    # No virtual MFA = hardware MFA
    mock_get_root_virtual_mfa_device.return_value = None

    result = check_root_mfa_enabled()

    # Verify the result
    assert result["check_id"] == "root-mfa-enabled"
    assert result["check_name"] == "Root MFA Enabled"
    assert result["status"] == "PASS"
    message = "Root MFA is enabled with hardware MFA device in the management account"
    assert message in result["details"]["message"]
    assert result["details"]["accounts_without_mfa"] == []
    assert result["details"]["accounts_with_virtual_mfa"] == []


def test_root_mfa_org_managed_virtual_mfa(
    mock_get_organization_features,
    mock_config,
    mock_get_account_summary,
    mock_get_root_virtual_mfa_device,
):
    """Test when root credentials are managed at org level.

    Verifies behavior when MFA is enabled with virtual device.
    """
    # Set up mocks
    mock_get_organization_features.return_value = ["RootCredentialsManagement"]
    mock_config.return_value = MagicMock(management_account_id="123456789012")
    mock_get_account_summary.return_value = {"AccountMFAEnabled": 1}
    arn = "arn:aws:iam::123456789012:mfa/root"
    mock_get_root_virtual_mfa_device.return_value = arn

    result = check_root_mfa_enabled()

    # Verify the result
    assert result["check_id"] == "root-mfa-enabled"
    assert result["check_name"] == "Root MFA Enabled"
    assert result["status"] == "FAIL"
    message = "Root MFA is enabled with virtual MFA devices in 1 accounts"
    assert message in result["details"]["message"]
    assert result["details"]["accounts_without_mfa"] == []
    assert result["details"]["accounts_with_virtual_mfa"] == ["123456789012"]


def test_root_mfa_org_managed_no_mfa(
    mock_get_organization_features,
    mock_config,
    mock_get_account_summary,
):
    """Test when root credentials are managed at org level.

    Verifies behavior when MFA is not enabled.
    """
    # Set up mocks
    mock_get_organization_features.return_value = ["RootCredentialsManagement"]
    mock_config.return_value = MagicMock(management_account_id="123456789012")
    mock_get_account_summary.return_value = {"AccountMFAEnabled": 0}

    result = check_root_mfa_enabled()

    # Verify the result
    assert result["check_id"] == "root-mfa-enabled"
    assert result["check_name"] == "Root MFA Enabled"
    assert result["status"] == "FAIL"
    message = "Root MFA is not enabled in 1 accounts"
    assert message in result["details"]["message"]
    assert result["details"]["accounts_without_mfa"] == ["123456789012"]
    assert result["details"]["accounts_with_virtual_mfa"] == []


def test_root_mfa_org_managed_no_mgmt_account(
    mock_get_organization_features,
    mock_config,
):
    """Test when root credentials are managed at org level.

    Verifies behavior when management account cannot be determined.
    """
    # Set up mocks
    mock_get_organization_features.return_value = ["RootCredentialsManagement"]
    mock_config.return_value = MagicMock(management_account_id=None)

    result = check_root_mfa_enabled()

    # Verify the result
    assert result["check_id"] == "root-mfa-enabled"
    assert result["check_name"] == "Root MFA Enabled"
    assert result["status"] == "ERROR"
    message = (
        "Root credentials management is enabled, but management account ID "
        "could not be determined"
    )
    assert message in result["details"]["message"]


def test_root_mfa_not_org_managed_pass(
    mock_get_organization_features,
    mock_config,
    mock_get_account_ids,
    mock_get_account_summary,
    mock_get_root_virtual_mfa_device,
):
    """Test when root credentials are not managed at org level.

    Verifies behavior when MFA is enabled with hardware devices.
    """
    # Set up mocks
    mock_get_organization_features.return_value = []
    mock_config.return_value = MagicMock(management_account_id="123456789012")
    mock_get_account_summary.return_value = {"AccountMFAEnabled": 1}
    # No virtual MFA = hardware MFA
    mock_get_root_virtual_mfa_device.return_value = None

    result = check_root_mfa_enabled()

    # Verify the result
    assert result["check_id"] == "root-mfa-enabled"
    assert result["check_name"] == "Root MFA Enabled"
    assert result["status"] == "PASS"
    message = "Root MFA is enabled with hardware MFA devices in all accounts"
    assert message in result["details"]["message"]
    assert result["details"]["accounts_without_mfa"] == []
    assert result["details"]["accounts_with_virtual_mfa"] == []


def test_root_mfa_not_org_managed_virtual_mfa(
    mock_get_organization_features,
    mock_config,
    mock_get_account_ids,
    mock_get_account_summary,
    mock_get_root_virtual_mfa_device,
):
    """Test when root credentials are not managed at org level.

    Verifies behavior when MFA is enabled with virtual devices.
    """
    # Set up mocks
    mock_get_organization_features.return_value = []
    mock_config.return_value = MagicMock(management_account_id="123456789012")
    mock_get_account_summary.return_value = {"AccountMFAEnabled": 1}
    arn = "arn:aws:iam::123456789012:mfa/root"
    mock_get_root_virtual_mfa_device.return_value = arn

    result = check_root_mfa_enabled()

    # Verify the result
    assert result["check_id"] == "root-mfa-enabled"
    assert result["check_name"] == "Root MFA Enabled"
    assert result["status"] == "FAIL"
    message = "Root MFA is enabled with virtual MFA devices in 2 accounts"
    assert message in result["details"]["message"]
    assert result["details"]["accounts_without_mfa"] == []
    assert result["details"]["accounts_with_virtual_mfa"] == [
        "123456789012",
        "098765432109",
    ]


def test_root_mfa_not_org_managed_no_mfa(
    mock_get_organization_features,
    mock_config,
    mock_get_account_ids,
    mock_get_account_summary,
    mock_get_root_virtual_mfa_device,
):
    """Test when root credentials are not managed at org level.

    Verifies behavior when MFA is not enabled.
    """
    # Set up mocks
    mock_get_organization_features.return_value = []
    mock_config.return_value = MagicMock(management_account_id="123456789012")
    mock_get_account_summary.return_value = {"AccountMFAEnabled": 0}

    result = check_root_mfa_enabled()

    # Verify the result
    assert result["check_id"] == "root-mfa-enabled"
    assert result["check_name"] == "Root MFA Enabled"
    assert result["status"] == "FAIL"
    message = "Root MFA is not enabled in 2 accounts"
    assert message in result["details"]["message"]
    assert result["details"]["accounts_without_mfa"] == [
        "123456789012",
        "098765432109",
    ]
    assert result["details"]["accounts_with_virtual_mfa"] == []


def test_root_mfa_error(
    mock_get_organization_features,
):
    """Test when an error occurs during the check."""
    # Set up mock to raise an exception
    mock_get_organization_features.side_effect = Exception("Test error")

    result = check_root_mfa_enabled()

    # Verify the result
    assert result["check_id"] == "root-mfa-enabled"
    assert result["check_name"] == "Root MFA Enabled"
    assert result["status"] == "ERROR"
    message = "Error checking for root MFA: Test error"
    assert message in result["details"]["message"]
