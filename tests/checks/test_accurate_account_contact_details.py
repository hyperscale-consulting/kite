import pytest

from kite.checks import AccurateAccountContactDetailsCheck
from kite.checks import CheckStatus
from tests.factories import config_for_org
from tests.factories import config_for_standalone_account
from tests.factories import create_organization
from tests.factories import create_organization_features

mgmt_account_id = "123456789012"


@pytest.fixture
def check():
    return AccurateAccountContactDetailsCheck()


@config_for_org(mgmt_account_id)
def test_credentials_management_enabled(check):
    create_organization(mgmt_account_id)
    create_organization_features(
        mgmt_account_id, features=["RootCredentialsManagement"]
    )
    result = check.run()
    assert result.status == CheckStatus.MANUAL
    assert "Root credentials management is enabled at the org level" in result.context


@config_for_org(mgmt_account_id)
def test_credentials_management_not_enabled(check):
    create_organization(mgmt_account_id)
    create_organization_features(mgmt_account_id, features=[])
    result = check.run()
    assert result.status == CheckStatus.MANUAL
    assert (
        "Root credentials management is not enabled at the org level" in result.context
    )


@config_for_standalone_account()
def test_standalone_account(check):
    result = check.run()
    assert result.status == CheckStatus.MANUAL
    assert "Root credentials management" not in result.context
