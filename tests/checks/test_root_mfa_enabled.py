from unittest.mock import patch

import pytest

from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.root_mfa_enabled import RootMfaEnabledCheck
from hyperscale.kite.data import save_account_summary
from hyperscale.kite.data import save_organization_features
from hyperscale.kite.data import save_virtual_mfa_devices
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization

mgmt_account_id = "123456789012"


@pytest.fixture
def check():
    return RootMfaEnabledCheck()


@pytest.fixture
def mock_get_organization_features():
    """Mock the get_organization_features function."""
    with patch("kite.checks.root_mfa_enabled.get_organization_features") as mock:
        yield mock


@pytest.fixture
def mock_config():
    """Mock the Config.get function."""
    with patch("kite.checks.root_mfa_enabled.Config.get") as mock:
        yield mock


@pytest.fixture
def mock_get_account_ids():
    """Mock the get_account_ids_in_scope function."""
    with patch("kite.checks.root_mfa_enabled.get_account_ids_in_scope") as mock:
        mock.return_value = ["123456789012", "098765432109"]
        yield mock


@pytest.fixture
def mock_get_account_summary():
    """Mock the get_account_summary function."""
    with patch("kite.checks.root_mfa_enabled.get_account_summary") as mock:
        yield mock


@pytest.fixture
def mock_get_root_virtual_mfa_device():
    """Mock the get_root_virtual_mfa_device function."""
    with patch("kite.checks.root_mfa_enabled.get_root_virtual_mfa_device") as mock:
        yield mock


def test_root_mfa_enabled_managed_credentials(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(mgmt_account_id=mgmt_account_id)
    save_organization_features(
        account_id=mgmt_account_id, features=["RootCredentialsManagement"]
    )
    save_account_summary(mgmt_account_id, {"AccountMFAEnabled": 1})
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert (
        "Root MFA is enabled with hardware MFA device in the management account"
        in result.reason
    )


def test_root_virtual_mfa_enabled_managed_credentials(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(mgmt_account_id=mgmt_account_id)
    save_organization_features(
        account_id=mgmt_account_id, features=["RootCredentialsManagement"]
    )
    save_account_summary(mgmt_account_id, {"AccountMFAEnabled": 1})
    save_virtual_mfa_devices(
        mgmt_account_id,
        [
            {
                "User": {"Arn": f"arn:aws:iam::${mgmt_account_id}:mfa/root"},
                "SerialNumber": "foo-mfa",
            }
        ],
    )
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "Root MFA is enabled with virtual MFA devices in 1 account" in result.reason


def test_no_root_mfa_managed_credentials(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(mgmt_account_id=mgmt_account_id)
    save_organization_features(
        account_id=mgmt_account_id, features=["RootCredentialsManagement"]
    )
    save_account_summary(mgmt_account_id, {"AccountMFAEnabled": 0})
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "Root MFA is not enabled in 1 account" in result.reason


def test_no_mgmt_account_id_configured_managed_credentials(check):
    create_config_for_standalone_account(account_ids=[mgmt_account_id])
    create_organization(mgmt_account_id=mgmt_account_id)
    save_organization_features(
        account_id=mgmt_account_id, features=["RootCredentialsManagement"]
    )
    save_account_summary(mgmt_account_id, {"AccountMFAEnabled": 1})
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert (
        "Root MFA is enabled with hardware MFA devices in all accounts" in result.reason
    )


def test_root_mfa_not_managed_credentials(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(mgmt_account_id=mgmt_account_id)
    save_account_summary(mgmt_account_id, {"AccountMFAEnabled": 1})
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert (
        "Root MFA is enabled with hardware MFA devices in all accounts" in result.reason
    )


def test_root_virtual_mfa_not_managed_credentials(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(mgmt_account_id=mgmt_account_id)
    save_account_summary(mgmt_account_id, {"AccountMFAEnabled": 1})
    save_virtual_mfa_devices(
        mgmt_account_id,
        [
            {
                "User": {"Arn": f"arn:aws:iam::${mgmt_account_id}:mfa/root"},
                "SerialNumber": "foo-mfa",
            }
        ],
    )
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "Root MFA is enabled with virtual MFA devices" in result.reason


def test_no_root_mfa_not_managed_credentials(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(mgmt_account_id=mgmt_account_id)
    save_account_summary(mgmt_account_id, {"AccountMFAEnabled": 0})
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "Root MFA is not enabled" in result.reason
