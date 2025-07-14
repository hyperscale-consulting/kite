import json

import pytest

from kite.checks.data_perimeter_trusted_resources.check import (
    check_data_perimeter_trusted_resources,
)
from kite.data import save_organization
from kite.models import ControlPolicy


@pytest.fixture
def trusted_resources_scp(organization_id):
    return ControlPolicy(
        id="123",
        name="ResourcePerimeter",
        description="Resource Perimeter",
        arn="arn:aws:iam::1234567890:policy/TrustedResources",
        type="SERVICE_CONTROL_POLICY",
        content=json.dumps(
            {
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
        ),
    )


@pytest.fixture
def scp_attached_to_root_ou(organization, trusted_resources_scp):
    organization.root.scps.append(trusted_resources_scp)
    save_organization(organization)
    yield organization


@pytest.fixture
def scp_attached_to_all_top_level_ous(organization, trusted_resources_scp):
    for ou in organization.root.child_ous:
        ou.scps.append(trusted_resources_scp)
    save_organization(organization)
    yield organization


def test_no_policies(organization):
    result = check_data_perimeter_trusted_resources()
    assert result["status"] == "FAIL"


def test_scp_attached_to_root_ou(scp_attached_to_root_ou):
    result = check_data_perimeter_trusted_resources()
    assert result["status"] == "PASS"


def test_scp_attached_to_all_top_level_ous(scp_attached_to_all_top_level_ous):
    result = check_data_perimeter_trusted_resources()
    assert result["status"] == "PASS"
