import json

import pytest

from kite.checks.data_perimeter_confused_deputy_protection import (
    check_data_perimeter_confused_deputy_protection,
)
from kite.data import save_organization
from kite.models import ControlPolicy


@pytest.fixture
def confused_deputy_protection_policy(organization_id):
    return ControlPolicy(
        id="123",
        name="Confused Deputy Protection",
        description="Confused Deputy Protection",
        arn="arn:aws:iam::1234567890:policy/ConfusedDeputyProtection",
        type="RESOURCE_CONTROL_POLICY",
        content=json.dumps(
            {
                "Statement": [
                    dict(
                        Effect="Deny",
                        Action=["s3:*", "sqs:*", "kms:*", "secretsmanager:*", "sts:*"],
                        Resource="*",
                        Principal="*",
                        Condition={
                            "StringNotEqualsIfExists": {
                                "aws:SourceOrgID": organization_id
                            },
                            "Null": {"AWS:SourceAccount": "false"},
                            "Bool": {"aws:PrincipalIsAWSService": "true"},
                        },
                    )
                ]
            }
        ),
    )


@pytest.fixture
def rcp_attached_to_root_ou(
    organization, confused_deputy_protection_policy, mgmt_account_id
):
    organization.root.rcps.append(confused_deputy_protection_policy)
    save_organization(mgmt_account_id, organization)
    yield organization


@pytest.fixture
def rcp_attached_to_all_top_level_ous(
    organization, confused_deputy_protection_policy, mgmt_account_id
):
    for ou in organization.root.child_ous:
        ou.rcps.append(confused_deputy_protection_policy)
    save_organization(mgmt_account_id, organization)
    yield organization


def test_no_rcps(organization):
    result = check_data_perimeter_confused_deputy_protection()
    assert result["status"] == "FAIL"


def test_rcp_attached_to_root_ou(rcp_attached_to_root_ou):
    result = check_data_perimeter_confused_deputy_protection()
    assert result["status"] == "PASS"


def test_rcp_attached_to_all_top_level_ous(rcp_attached_to_all_top_level_ous):
    result = check_data_perimeter_confused_deputy_protection()
    assert result["status"] == "PASS"
