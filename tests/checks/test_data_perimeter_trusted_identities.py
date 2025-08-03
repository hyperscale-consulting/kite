import pytest

from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.data_perimeter_trusted_identities import (
    DataPerimeterTrustedIdentitiesCheck,
)
from hyperscale.kite.data import save_organization
from tests.factories import build_ou
from tests.factories import build_rcp
from tests.factories import create_config_for_org
from tests.factories import create_organization

org_id = "o-1234567890"


def trusted_identities_policy():
    return {
        "Statement": [
            dict(
                Effect="Deny",
                Action=[
                    "s3:*",
                    "sqs:*",
                    "kms:*",
                    "secretsmanager:*",
                    "sts:AssumeRole",
                    "sts:DecodeAuthorizationMessage",
                    "sts:GetAccessKeyInfo",
                    "sts:GetFederationToken",
                    "sts:GetServiceBearerToken",
                    "sts:GetSessionToken",
                    "sts:SetContext",
                ],
                Resource="*",
                Principal="*",
                Condition={
                    "StringNotEqualsIfExists": {
                        "aws:PrincipalOrgID": org_id,
                        "aws:ResourceTag/dp:exclude:identity": "true",
                    },
                    "BoolIfExists": {"aws:PrincipalIsAWSService": "false"},
                },
            )
        ]
    }


@pytest.fixture
def rcp_attached_to_root_ou(organization, trusted_identities_policy, mgmt_account_id):
    organization.root.rcps.append(trusted_identities_policy)
    save_organization(mgmt_account_id, organization)
    yield organization


@pytest.fixture
def rcp_attached_to_all_top_level_ous(
    organization, trusted_identities_policy, mgmt_account_id
):
    for ou in organization.root.child_ous:
        ou.rcps.append(trusted_identities_policy)
    save_organization(mgmt_account_id, organization)
    yield organization


@pytest.fixture
def check():
    return DataPerimeterTrustedIdentitiesCheck()


def test_no_policies(check):
    create_config_for_org()
    create_organization(
        organization_id=org_id,
    )
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "protection is not attached" in result.reason


def test_rcp_attached_to_root_ou(check):
    create_config_for_org()
    create_organization(
        organization_id=org_id,
        root_ou=build_ou(rcps=[build_rcp(content=trusted_identities_policy())]),
    )
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert "protection is attached to the root OU" in result.reason


def test_rcp_attached_to_all_top_level_ous(check):
    create_config_for_org()
    create_organization(
        organization_id=org_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(rcps=[build_rcp(content=trusted_identities_policy())]),
                build_ou(rcps=[build_rcp(content=trusted_identities_policy())]),
            ]
        ),
    )
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert "protection is attached to all top-level OUs" in result.reason
