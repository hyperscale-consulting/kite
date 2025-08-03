import pytest

from hyperscale.kite.checks import AccurateAccountContactDetailsCheck
from hyperscale.kite.checks import CheckStatus
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization
from tests.factories import create_organization_features

mgmt_account_id = "123456789012"


@pytest.fixture
def check():
    return AccurateAccountContactDetailsCheck()


def test_credentials_management_enabled(check):
    create_config_for_org(mgmt_account_id)
    create_organization(mgmt_account_id)
    create_organization_features(
        mgmt_account_id, features=["RootCredentialsManagement"]
    )
    result = check.run()
    assert result.status == CheckStatus.MANUAL
    assert "Root credentials management is enabled at the org level" in result.context


def test_credentials_management_not_enabled(check):
    create_config_for_org(mgmt_account_id)
    create_organization(mgmt_account_id)
    create_organization_features(mgmt_account_id, features=[])
    result = check.run()
    assert result.status == CheckStatus.MANUAL
    assert (
        "Root credentials management is not enabled at the org level" in result.context
    )


def test_standalone_account(check):
    create_config_for_standalone_account()
    result = check.run()
    assert result.status == CheckStatus.MANUAL
    assert "Root credentials management" not in result.context
