import pytest

from kite.checks.root_credentials_management_enabled import (
    check_root_credentials_management_enabled,
)
from kite.data import save_organization_features


@pytest.fixture
def root_credentials_management_enabled(mgmt_account_id):
    save_organization_features(mgmt_account_id, ["RootCredentialsManagement"])


@pytest.fixture
def root_credentials_management_not_enabled(mgmt_account_id):
    save_organization_features(mgmt_account_id, ["RootSessions"])


@pytest.fixture
def no_features(mgmt_account_id):
    save_organization_features(mgmt_account_id, [])


def test_root_credentials_management_enabled(root_credentials_management_enabled):
    """Test when root credentials management is enabled."""
    # Set up mock to return features with root credentials management enabled
    result = check_root_credentials_management_enabled()

    assert result["status"] == "PASS"
    assert (
        "Root credentials management is enabled at the organizational level"
        in result["details"]["message"]
    )


def test_root_credentials_management_not_enabled(
    root_credentials_management_not_enabled,
):
    """Test when root credentials management is not enabled."""

    result = check_root_credentials_management_enabled()

    assert result["status"] == "FAIL"
    assert (
        "Root credentials management is not enabled at the organizational level"
        in result["details"]["message"]
    )


def test_no_features(no_features):
    """Test when no features are enabled."""
    result = check_root_credentials_management_enabled()

    assert result["status"] == "FAIL"
    assert (
        "Root credentials management is not enabled at the organizational level"
        in result["details"]["message"]
    )
