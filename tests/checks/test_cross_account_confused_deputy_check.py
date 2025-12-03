import pytest

from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.cross_account_confused_deputy_prevention import (
    CrossAccountConfusedDeputyPreventionCheck,
)
from hyperscale.kite.data import save_roles
from tests.factories import build_account
from tests.factories import build_ou
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization

mgmt_account_id = "1111111111111"
workload_account_id = "222222222222"


@pytest.fixture
def check():
    return CrossAccountConfusedDeputyPreventionCheck()


def service_role():
    role = {
        "Path": "/",
        "RoleName": "TestRole",
        "RoleId": "AROATCKAQYCTHD2YTLKMK",
        "Arn": f"arn:aws:iam::{workload_account_id}:role/TestRole",
        "CreateDate": "2024-12-04 10:54:27+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        "MaxSessionDuration": 43200,
        "AttachedPolicies": [
            {
                "PolicyName": "AdministratorAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            }
        ],
        "InlinePolicies": [],
    }
    save_roles(workload_account_id, [role])


def external_role_no_external_id_condition():
    role = {
        "Path": "/",
        "RoleName": "ExternalRole",
        "RoleId": "AROATCKAQYCTHD2YTLKMK",
        "Arn": f"arn:aws:iam::{workload_account_id}:role/ExternalRole",
        "CreateDate": "2025-05-09 12:32:29+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:sts::191919191919:assumed-role/ExternalRoleXyz"
                    },
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        "Description": "",
        "MaxSessionDuration": 3600,
        "AttachedPolicies": [
            {
                "PolicyName": "SecurityAudit",
                "PolicyArn": "arn:aws:iam::aws:policy/SecurityAudit",
            },
        ],
        "InlinePolicies": [],
    }
    save_roles(workload_account_id, [role])


def external_role_with_external_id_condition():
    role = {
        "Path": "/",
        "RoleName": "ExternalRole",
        "RoleId": "AROATCKAQYCTHD2YTLKMK",
        "Arn": f"arn:aws:iam::{workload_account_id}:role/ExternalRole",
        "CreateDate": "2025-05-09 12:32:29+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:sts::999999999999:assumed-role/ExternalRoleXyz"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": "xyz-1234"}},
                }
            ],
        },
        "Description": "",
        "MaxSessionDuration": 3600,
        "AttachedPolicies": [
            {
                "PolicyName": "SecurityAudit",
                "PolicyArn": "arn:aws:iam::aws:policy/SecurityAudit",
            },
        ],
        "InlinePolicies": [],
    }
    save_roles(workload_account_id, [role])


def identity_center_role():
    role = {
        "Path": "/aws-reserved/sso.amazonaws.com/eu-north-1/",
        "RoleName": "AWSReservedSSO_AdministratorAccess_0c2c54f4de53553c",
        "RoleId": "AROAXKPUZWAPJC3NDHNNS",
        "Arn": (
            f"arn:aws:iam::{workload_account_id}:role/aws-reserved/sso.amazonaws.com/eu-north-1/AWSReservedSSO_AdministratorAccess_0c2c54f4de53553c"
        ),
        "CreateDate": "2024-12-04 10:54:27+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": (
                            f"arn:aws:iam::{workload_account_id}:saml-provider/AWSSSO_aec96f586b16dacc_DO_NOT_DELETE"
                        )
                    },
                    "Action": ["sts:AssumeRoleWithSAML", "sts:TagSession"],
                    "Condition": {
                        "StringEquals": {
                            "SAML:aud": "https://signin.aws.amazon.com/saml"
                        }
                    },
                }
            ],
        },
        "MaxSessionDuration": 43200,
        "AttachedPolicies": [
            {
                "PolicyName": "AdministratorAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            }
        ],
        "InlinePolicies": [],
    }
    save_roles(workload_account_id, [role])


def no_org_config():
    create_config_for_standalone_account(account_ids=[workload_account_id])


def org_config():
    create_config_for_org(
        mgmt_account_id=mgmt_account_id,
        account_ids=[workload_account_id],
    )
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(accounts=[build_account(id=workload_account_id)]),
            ]
        ),
    )
    yield


def test_service_role(check):
    create_config_for_standalone_account(account_ids=[workload_account_id])
    service_role()
    assert check.run().status == CheckStatus.PASS


def test_external_role_no_external_id_condition(check):
    create_config_for_standalone_account(account_ids=[workload_account_id])
    external_role_no_external_id_condition()
    assert check.run().status == CheckStatus.FAIL


def test_external_role_with_external_id_condition(check):
    create_config_for_standalone_account(account_ids=[workload_account_id])
    external_role_with_external_id_condition()
    assert check.run().status == CheckStatus.PASS


def test_identity_center_role(check):
    create_config_for_standalone_account(account_ids=[workload_account_id])
    identity_center_role()
    assert check.run().status == CheckStatus.PASS
