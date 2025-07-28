import pytest

from kite.checks.core import CheckStatus
from kite.checks.root_credentials_management_enabled import (
    RootCredentialsManagementEnabledCheck,
)
from kite.data import save_organization_features
from tests.factories import config_for_org
from tests.factories import config_for_standalone_account
from tests.factories import create_organization

mgmt_account_id = "123456789012"


@pytest.fixture
def check():
    return RootCredentialsManagementEnabledCheck()


@config_for_org(mgmt_account_id)
def test_credentials_management_enabled(check):
    create_organization(mgmt_account_id)
    save_organization_features(mgmt_account_id, ["RootCredentialsManagement"])
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert (
        "Root credentials management is enabled at the organizational level"
        in result.reason
    )


@config_for_org(mgmt_account_id)
def test_credentials_management_not_enabled(check):
    create_organization(mgmt_account_id)
    save_organization_features(mgmt_account_id, ["RootSessions"])
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert (
        "Root credentials management is not enabled at the organizational level"
        in result.reason
    )


@config_for_org(mgmt_account_id)
def test_no_features(check):
    create_organization(mgmt_account_id)
    save_organization_features(mgmt_account_id, [])
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert (
        "Root credentials management is not enabled at the organizational level"
        in result.reason
    )


@config_for_standalone_account(mgmt_account_id)
def test_no_org(check):
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert (
        "Root credentials management is not enabled at the organizational level"
        in result.reason
    )
