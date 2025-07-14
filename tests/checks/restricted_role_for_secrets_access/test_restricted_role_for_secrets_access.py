from unittest.mock import patch

import pytest

from kite.checks.restricted_role_for_secrets_access.check import (
    check_restricted_role_for_secrets_access,
)
from kite.data import save_roles
from kite.data import save_secrets


@pytest.fixture
def mock_manual_check():
    with patch(
        "kite.checks.restricted_role_for_secrets_access.check.manual_check"
    ) as mock:
        yield mock


def test_restricted_role(workload_account_id, organization, mock_manual_check):
    mock_manual_check.return_value = {"status": "PASS"}
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
                            "aws:PrincipalArn": f"arn:aws:iam::{workload_account_id}:role/SecretAdmin"
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

    results = check_restricted_role_for_secrets_access()
    assert results["status"] == "PASS"
    mock_manual_check.assert_called_once()
    _, kwargs = mock_manual_check.call_args
    assert kwargs["check_id"] == "restricted-role-for-secrets-access"
    assert kwargs["check_name"] == "Restricted Role for Secrets Access"
    assert (
        "Principals found in deny exception conditions:\n\n"
        f"- arn:aws:iam::{workload_account_id}:role/SecretAdmin\n"
        "  Principals allowed to assume this role:\n"
        "  - {'AWS': 'arn:aws:iam::123456789012:user/Bob'}\n"
    ) in kwargs.get("message", "")


def test_no_secrets(organization, mock_manual_check):
    results = check_restricted_role_for_secrets_access()
    assert results["status"] == "PASS"
    mock_manual_check.assert_not_called()  # should pass the check automatically


def test_no_resource_policy(workload_account_id, organization, mock_manual_check):
    mock_manual_check.return_value = {"status": "FAIL"}
    secret = {
        "Name": "SecretWithNoResourcePolicy",
        "ARN": f"arn:aws:secretsmanager:us-east-1:{workload_account_id}:secret:SecretWithNoResourcePolicy",
    }
    save_secrets(workload_account_id, "us-east-1", [secret])

    results = check_restricted_role_for_secrets_access()
    assert results["status"] == "FAIL"
    mock_manual_check.assert_called_once()
    _, kwargs = mock_manual_check.call_args
    assert kwargs["check_id"] == "restricted-role-for-secrets-access"
    assert kwargs["check_name"] == "Restricted Role for Secrets Access"
    assert (
        "Secrets without resource policies:\n"
        f"- SecretWithNoResourcePolicy in account {workload_account_id} region us-east-1\n"
    ) in kwargs.get("message", "")


def test_no_deny_statements(workload_account_id, organization, mock_manual_check):
    mock_manual_check.return_value = {"status": "FAIL"}
    secret = {
        "Name": "SecretWithNoDenyStatements",
        "ARN": f"arn:aws:secretsmanager:us-east-1:{workload_account_id}:secret:SecretWithNoDenyStatements",
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

    results = check_restricted_role_for_secrets_access()
    assert results["status"] == "FAIL"
    mock_manual_check.assert_called_once()
    _, kwargs = mock_manual_check.call_args
    assert kwargs["check_id"] == "restricted-role-for-secrets-access"
    assert kwargs["check_name"] == "Restricted Role for Secrets Access"
    assert (
        "Secrets without deny statements:\n"
        f"- SecretWithNoDenyStatements in account {workload_account_id} region us-east-1\n"
    ) in kwargs.get("message", "")
