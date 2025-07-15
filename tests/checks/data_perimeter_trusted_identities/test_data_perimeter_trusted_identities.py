import json

import pytest

from kite.checks.data_perimeter_trusted_identities.check import (
    check_establish_data_perimeter_trusted_identities,
)
from kite.data import save_organization
from kite.models import ControlPolicy


@pytest.fixture
def trusted_identities_policy(organization_id):
    return ControlPolicy(
        id="123",
        name="Trusted Identities Protection",
        description="Trusted Identities Protection",
        arn="arn:aws:iam::1234567890:policy/TrustedIdentitiesProtection",
        type="RESOURCE_CONTROL_POLICY",
        content=json.dumps(
            {
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
                                "aws:PrincipalOrgID": organization_id,
                                "aws:ResourceTag/dp:exclude:identity": "true",
                            },
                            "BoolIfExists": {"aws:PrincipalIsAWSService": "false"},
                        },
                    )
                ]
            }
        ),
    )


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


def test_no_policies(organization):
    result = check_establish_data_perimeter_trusted_identities()
    assert result["status"] == "FAIL"


def test_rcp_attached_to_root_ou(rcp_attached_to_root_ou):
    result = check_establish_data_perimeter_trusted_identities()
    assert result["status"] == "PASS"


def test_rcp_attached_to_all_top_level_ous(rcp_attached_to_all_top_level_ous):
    result = check_establish_data_perimeter_trusted_identities()
    assert result["status"] == "PASS"
