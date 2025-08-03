import pytest

from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks.data_perimeter_trusted_resources import (
    DataPerimeterTrustedResourcesCheck,
)
from hyperscale.kite.data import save_organization
from tests.factories import build_ou
from tests.factories import build_scp
from tests.factories import create_config_for_org
from tests.factories import create_organization

organization_id = "test-org-id"


def trusted_resources_scp():
    return {
        "Statement": [
            dict(
                Effect="Deny",
                NotAction=[
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "iam:ListEntitiesForPolicy",
                    "iam:ListPolicyVersions",
                    "iam:GenerateServiceLastAccessedDetails",
                    "cloudformation:CreateChangeSet",
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                    "s3:PutObjectAcl",
                    "s3:ListBucket",
                    "ssm:Describe*",
                    "ssm:List*",
                    "ssm:Get*",
                    "ssm:SendCommand",
                    "ssm:CreateAssociation",
                    "ssm:StartSession",
                    "ssm:StartChangeRequestExecution",
                    "ssm:StartAutomationExecution",
                    "imagebuilder:GetComponent",
                    "imagebuilder:GetImage",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:BatchGetImage",
                    "lambda:GetLayerVersion",
                    "ec2:CreateTags",
                    "ec2:DeleteTags",
                    "ec2:GetManagedPrefixListEntries",
                ],
                Resource="*",
                Principal="*",
                Condition={
                    "StringNotEqualsIfExists": {
                        "AWS:ResourceOrgID": organization_id,
                        "aws:PrincipalTag/dp:exclude:resource": "true",
                    }
                },
            )
        ]
    }


@pytest.fixture
def scp_attached_to_root_ou(organization, trusted_resources_scp, mgmt_account_id):
    organization.root.scps.append(trusted_resources_scp)
    save_organization(mgmt_account_id, organization)
    yield organization


@pytest.fixture
def scp_attached_to_all_top_level_ous(
    organization, trusted_resources_scp, mgmt_account_id
):
    for ou in organization.root.child_ous:
        ou.scps.append(trusted_resources_scp)
    save_organization(mgmt_account_id, organization)
    yield organization


@pytest.fixture
def check():
    return DataPerimeterTrustedResourcesCheck()


def test_no_policies(check):
    create_config_for_org()
    create_organization(organization_id=organization_id)
    result = check.run()
    assert result.status == CheckStatus.FAIL


def test_scp_attached_to_root_ou(check):
    create_config_for_org()
    create_organization(
        organization_id=organization_id,
        root_ou=build_ou(scps=[build_scp(content=trusted_resources_scp())]),
    )
    result = check.run()
    assert result.status == CheckStatus.PASS


def test_scp_attached_to_all_top_level_ous(check):
    create_config_for_org()
    create_organization(
        organization_id=organization_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(name="OU1", scps=[build_scp(content=trusted_resources_scp())]),
                build_ou(name="OU2", scps=[build_scp(content=trusted_resources_scp())]),
            ]
        ),
    )
    result = check.run()
    assert result.status == CheckStatus.PASS
