import pytest

from kite.checks import CheckStatus
from kite.checks.data_perimeter_confused_deputy_protection import (
    DataPerimeterConfusedDeputyProtectionCheck,
)
from tests.factories import build_ou
from tests.factories import build_rcp
from tests.factories import config_for_org
from tests.factories import create_organization

org_id = "test-org-id"


def confused_deputy_protection_policy():
    return {
        "Statement": [
            dict(
                Effect="Deny",
                Action=["s3:*", "sqs:*", "kms:*", "secretsmanager:*", "sts:*"],
                Resource="*",
                Principal="*",
                Condition={
                    "StringNotEqualsIfExists": {"aws:SourceOrgID": org_id},
                    "Null": {"AWS:SourceAccount": "false"},
                    "Bool": {"aws:PrincipalIsAWSService": "true"},
                },
            )
        ]
    }


@pytest.fixture
def check():
    return DataPerimeterConfusedDeputyProtectionCheck()


@config_for_org(mgmt_account_id="1234567890")
def test_no_rcps(check):
    create_organization(organization_id=org_id, mgmt_account_id="1234567890")
    result = check.run()
    assert result.status == CheckStatus.FAIL


@config_for_org(mgmt_account_id="1234567890")
def test_rcp_attached_to_root_ou(check):
    create_organization(
        organization_id=org_id,
        mgmt_account_id="1234567890",
        root_ou=build_ou(rcps=[build_rcp(content=confused_deputy_protection_policy())]),
    )
    result = check.run()
    assert result.status == CheckStatus.PASS


@config_for_org(mgmt_account_id="1234567890")
def test_rcp_attached_to_all_top_level_ous(check):
    create_organization(
        organization_id=org_id,
        mgmt_account_id="1234567890",
        root_ou=build_ou(
            child_ous=[
                build_ou(
                    name="OU1",
                    rcps=[build_rcp(content=confused_deputy_protection_policy())],
                ),
                build_ou(
                    name="OU2",
                    rcps=[build_rcp(content=confused_deputy_protection_policy())],
                ),
            ]
        ),
    )

    result = check.run()
    assert result.status == CheckStatus.PASS


@config_for_org(mgmt_account_id="1234567890")
def test_rcp_attached_to_one_top_level_ous(check):
    create_organization(
        organization_id=org_id,
        mgmt_account_id="1234567890",
        root_ou=build_ou(
            child_ous=[
                build_ou(
                    name="OU1",
                    rcps=[],
                ),
                build_ou(
                    name="OU2",
                    rcps=[build_rcp(content=confused_deputy_protection_policy())],
                ),
            ]
        ),
    )

    result = check.run()
    assert result.status == CheckStatus.FAIL
