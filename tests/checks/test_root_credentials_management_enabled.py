import pytest

from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.root_credentials_management_enabled import (
    RootCredentialsManagementEnabledCheck,
)
from hyperscale.kite.data import save_organization_features
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization

mgmt_account_id = "123456789012"


@pytest.fixture
def check():
    return RootCredentialsManagementEnabledCheck()


def test_credentials_management_enabled(check):
    create_config_for_org(mgmt_account_id)
    create_organization(mgmt_account_id)
    save_organization_features(mgmt_account_id, ["RootCredentialsManagement"])
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert (
        "Root credentials management is enabled at the organizational level"
        in result.reason
    )


def test_credentials_management_not_enabled(check):
    create_config_for_org(mgmt_account_id)
    create_organization(mgmt_account_id)
    save_organization_features(mgmt_account_id, ["RootSessions"])
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert (
        "Root credentials management is not enabled at the organizational level"
        in result.reason
    )


def test_no_features(check):
    create_config_for_org(mgmt_account_id)
    create_organization(mgmt_account_id)
    save_organization_features(mgmt_account_id, [])
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert (
        "Root credentials management is not enabled at the organizational level"
        in result.reason
    )


def test_no_org(check):
    create_config_for_standalone_account(mgmt_account_id)
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert (
        "Root credentials management is not enabled at the organizational level"
        in result.reason
    )
