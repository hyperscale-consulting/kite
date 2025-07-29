import pytest

from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.restricted_role_for_secrets_access import (
    RestrictedRoleForSecretsAccessCheck,
)
from hyperscale.kite.data import save_roles
from hyperscale.kite.data import save_secrets


@pytest.fixture
def check():
    return RestrictedRoleForSecretsAccessCheck()


def test_restricted_role(workload_account_id, organization, check):
    secret = {
        "ResourcePolicy": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{workload_account_id}:role/SecretAdmin"
                    },
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "aws:PrincipalArn": (
                                f"arn:aws:iam::{workload_account_id}:role/SecretAdmin"
                            )
                        }
                    },
                },
            ]
        }
    }
    save_secrets(workload_account_id, "us-east-1", [secret])
    role = {
        "RoleArn": f"arn:aws:iam::{workload_account_id}:role/SecretAdmin",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/Bob"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    }
    save_roles(workload_account_id, [role])

    result = check.run()

    assert check.check_id == "restricted-role-for-secrets-access"
    assert check.check_name == "Restricted Role for Secrets Access"
    assert result.status == CheckStatus.MANUAL
    assert result.context is not None
    assert (f"arn:aws:iam::{workload_account_id}:role/SecretAdmin") in result.context
    assert "arn:aws:iam::123456789012:user/Bob" in result.context


def test_no_secrets(organization, check):
    result = check.run()

    assert result.status == CheckStatus.PASS
    assert result.reason is not None
    assert "No secrets found" in result.reason


def test_no_resource_policy(workload_account_id, organization, check):
    secret = {
        "Name": "SecretWithNoResourcePolicy",
        "ARN": (
            f"arn:aws:secretsmanager:us-east-1:{workload_account_id}:"
            "secret:SecretWithNoResourcePolicy"
        ),
    }
    save_secrets(workload_account_id, "us-east-1", [secret])

    result = check.run()

    assert result.status == CheckStatus.MANUAL
    assert result.context is not None
    assert "SecretWithNoResourcePolicy" in result.context


def test_no_deny_statements(workload_account_id, organization, check):
    secret = {
        "Name": "SecretWithNoDenyStatements",
        "ARN": (
            f"arn:aws:secretsmanager:us-east-1:{workload_account_id}:"
            "secret:SecretWithNoDenyStatements"
        ),
        "ResourcePolicy": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{workload_account_id}:role/SecretAdmin"
                    },
                },
            ]
        },
    }
    save_secrets(workload_account_id, "us-east-1", [secret])

    result = check.run()

    assert result.status == CheckStatus.MANUAL
    assert result.context is not None
    assert "SecretWithNoDenyStatements" in result.context
