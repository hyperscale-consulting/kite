import pytest

from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks.require_mfa import RequireMfaCheck
from hyperscale.kite.data import save_cognito_user_pools
from hyperscale.kite.data import save_credentials_report
from hyperscale.kite.data import save_identity_center_instances
from hyperscale.kite.data import save_saml_providers
from tests.factories import create_config_for_org
from tests.factories import create_organization

mgmt_account_id = "111111111111"


@pytest.fixture
def check():
    return RequireMfaCheck()


def test_check(check):
    create_config_for_org(mgmt_account_id)
    create_organization(mgmt_account_id)
    saml_providers = [
        {
            "Arn": "arn:aws:iam::111111111111:saml-provider/MySAMLProvider",
        }
    ]
    save_saml_providers(mgmt_account_id, saml_providers)
    identity_center_instances = [
        {
            "InstanceArn": "arn:aws:sso:::instance/ssoins-ffffffffffffffff",
        }
    ]
    save_identity_center_instances(mgmt_account_id, identity_center_instances)
    credentials_report = {
        "users": [
            {
                "user": "bob",
                "arn": "arn:aws:iam::111111111111:user/bob",
                "mfa_active": "false",
            }
        ]
    }
    save_credentials_report(mgmt_account_id, credentials_report)
    user_pools = [{"Id": "foo-up", "Name": "Foo-user-pool", "MfaConfiguration": "OFF"}]
    save_cognito_user_pools(mgmt_account_id, "eu-west-2", user_pools)

    result = check.run()
    assert result.status == CheckStatus.MANUAL
    assert (
        "SAML Providers Found:\n"
        "- arn:aws:iam::111111111111:saml-provider/MySAMLProvider" in result.context
    )
    assert "Identity Center enabled: Yes" in result.context
    assert "IAM Users without MFA:\n- bob (111111111111)" in result.context
    assert "IAM Users were found"
    assert (
        "Cognito User Pools without MFA Required:\n"
        "- Foo-user-pool (111111111111) - MFA: OFF" in result.context
    )
