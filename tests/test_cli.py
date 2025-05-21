"""Tests for the CLI module."""

from pathlib import Path
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from kite.config import Config
from kite.cli import main
from kite.models import DelegatedAdmin, EC2Instance
from kite import (
    organizations,
    sts,
    ecs,
    ec2,
    eks,
    lambda_,
    rds,
    dynamodb,
    redshift,
    sagemaker,
    sns,
    sqs,
    kms,
    s3,
    cloudfront,
    iam,
    identity_center,
)


@pytest.fixture
def config_path(tmp_path: Path, config: Config):
    path = tmp_path / "kite.yaml"
    config.save(str(path))
    yield path
    if path.exists():
        path.unlink()


@pytest.fixture
def delegated_admins(audit_account_id):
    yield [DelegatedAdmin(id=audit_account_id,
                          arn=f"arn:aws:organizations:::{audit_account_id}:account",
                          email="audit@example.com",
                          name="Audit Account",
                          status="ACTIVE",
                          joined_method="CREATED",
                          joined_timestamp="2021-01-01T00:00:00Z",
                          delegation_enabled_date="2021-01-01T00:00:00Z",
                          service_principal="securityhub.amazonaws.com")]


@pytest.fixture
def ec2_instances():

    yield [EC2Instance(instance_id="asdfasfasdf",
                       instance_type="t3.micro",
                       state="running",
                       region="us-west-2")]


@pytest.fixture
def organization_features():
    yield {
        "features": [
            "RootSessions",
            "RootCredentialsManagement"
        ]
    }


@pytest.fixture
def credentials_report():
    yield {
        "root": {
            "user": "<root_account>",
            "password_last_used": "2021-01-01T00:00:00Z",
        },
        "users": [
            {
                "user": "user1",
                "mfa_active": "true",
            },
            {
                "user": "user2",
                "mfa_active": "false",
            }
        ]
    }


@pytest.fixture
def account_summary():
    yield {
        "AccountMFAEnabled": 1,
        "AccountAccessKeysPresent": 0,
    }


@pytest.fixture
def virtual_mfa_devices():
    return [{
        "SerialNumber": "arn:aws:iam::123456789012:mfa/root",
        "User": {"Arn": "arn:aws:iam::123456789012:root"},
    }, {
        "SerialNumber": "arn:aws:iam::123456789012:mfa/user1",
        "User": {"Arn": "arn:aws:iam::123456789012:user/user1"},
    }]


@pytest.fixture
def password_policy():
    yield {
        "MinimumPasswordLength": 8,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "AllowUsersToChangePassword": True,
        "ExpirePasswords": True,
        "PasswordReusePrevention": 5,
    }


@pytest.fixture
def iam_rotate_access_key_90_days_prowler_result():
    fields = ["" for _ in range(26)]
    fields[10] = "iam_rotate_access_key_90_days"
    fields[13] = "PASS"
    fields[14] = "PASS"
    fields[20] = "arn:aws:iam::123456789012:user/user1"
    fields[21] = "user1"
    fields[22] = "IAM user"
    fields[25] = "us-east-1"
    yield fields


@pytest.fixture
def workload_account_prowler_output(workload_account_id, prowler_output_dir,
                                    iam_rotate_access_key_90_days_prowler_result):
    path = prowler_output_dir / f"prowler-output-{workload_account_id}.csv"
    with open(path, "w") as f:
        f.write(";".join(iam_rotate_access_key_90_days_prowler_result) + "\n")
    return path


@pytest.fixture
def prowler_output(workload_account_prowler_output):
    pass


@pytest.fixture
def runner(
    monkeypatch,
    config,
    organization,
    organization_features,
    account_summary,
    delegated_admins,
    credentials_report,
    virtual_mfa_devices,
    prowler_output,
    password_policy,
    ec2_instances,
):
    monkeypatch.setattr(sts, "assume_role", lambda *args, **kwargs: Mock())
    monkeypatch.setattr(organizations, "fetch_organization",
                        lambda *args, **kwargs: organization)
    monkeypatch.setattr(organizations, "fetch_delegated_admins",
                        lambda *args, **kwargs: delegated_admins)
    monkeypatch.setattr(ec2, "get_running_instances",
                        lambda *args, **kwargs: ec2_instances)
    monkeypatch.setattr(ecs, "get_clusters", lambda *args, **kwargs: [])
    monkeypatch.setattr(eks, "get_clusters", lambda *args, **kwargs: [])
    monkeypatch.setattr(lambda_, "get_functions", lambda *args, **kwargs: [])
    monkeypatch.setattr(rds, "get_instances", lambda *args, **kwargs: [])
    monkeypatch.setattr(dynamodb, "get_tables", lambda *args, **kwargs: [])
    monkeypatch.setattr(redshift, "get_clusters", lambda *args, **kwargs: [])
    monkeypatch.setattr(sagemaker, "get_notebook_instances", lambda *args, **kwargs: [])
    monkeypatch.setattr(sns, "get_topics", lambda *args, **kwargs: [])
    monkeypatch.setattr(sqs, "get_queues", lambda *args, **kwargs: [])
    monkeypatch.setattr(kms, "get_keys", lambda *args, **kwargs: [])
    monkeypatch.setattr(s3, "get_buckets", lambda *args, **kwargs: [])
    monkeypatch.setattr(cloudfront, "get_distributions", lambda *args, **kwargs: [])
    monkeypatch.setattr(iam, "fetch_organization_features",
                        lambda *args, **kwargs: organization_features)
    monkeypatch.setattr(iam, "fetch_credentials_report",
                        lambda *args, **kwargs: credentials_report)
    monkeypatch.setattr(iam, "fetch_account_summary",
                        lambda *args, **kwargs: account_summary)
    monkeypatch.setattr(iam, "list_saml_providers", lambda *args, **kwargs: [])
    monkeypatch.setattr(iam, "list_oidc_providers", lambda *args, **kwargs: [])
    monkeypatch.setattr(identity_center, "list_identity_center_instances",
                        lambda *args, **kwargs: [])
    monkeypatch.setattr(iam, "fetch_virtual_mfa_devices",
                        lambda *args, **kwargs: virtual_mfa_devices)
    monkeypatch.setattr(iam, "get_password_policy",
                        lambda *args, **kwargs: password_policy)
    runner = CliRunner()
    with runner.isolated_filesystem():
        yield runner


def test_run_list_checks(runner, config):
    result = runner.invoke(main, ["list-checks"])
    assert result.exit_code == 0


def test_run_start_without_collect(runner, config_path):
    result = runner.invoke(main, ["start", "--config", str(config_path)])
    assert (
        "Data collection has not been run. Please run 'kite collect' first."
        in result.output
    )
    assert result.exit_code != 0


def test_run_collect(runner, config_path):
    result = runner.invoke(main, ["collect", "--config", str(config_path)])
    assert "Data collection complete" in result.output
    assert result.exit_code == 0


def test_run_start_after_collect(runner, config_path):
    runner.invoke(main, ["collect", "--config", str(config_path)])

    input = [
        'y',
        'Effective account separation in place',
        'y',
        'Effective OU Structure in place',
        'n',
        'Workloads in management account',
        'y',
        'Delegated admin is trusted',
        'y',
        'Contact details are accurate',
        'y',
        'Root account is monitored for abuse',
        'y',
        'Root account credentials are stored securely',
        'y',
        'Root account access is tested periodically',
        'y',
        'Control objectives are well-defined',
        'y',
        'Security controls implemented',
        'y',
        'Threat intel is used',
        'y',
        'Tech inventories are up to date',
        'y',
        'Workloads can me quickly updated',
        'y',
        'Managed services are used for threat intel',
        'n',
        'EC2 widely used',
        'y',
        'AWS compliance docs used',
        'y',
        'Teams keep up to date with new services',
        'y',
        'IaC used',
        'y',
        'IaC in VCS',
        'y',
        'IaC guardrails in place',
        'y',
        'Service catalog used',
        'y',
        'Accounts vended with security controls',
        'y',
        'Control tower used',
        'n',
        'No threat modeling',
        'n',
        'No DFDs',
        'n',
        'Security risks not identified',
        'y',
        'Services are evaluated',
        'y',
        'MFA enforced',
        ''
    ]
    result = runner.invoke(main, ["start", "--config", str(config_path)],
                           input='\n'.join(input))
    print(result.output)
    assert result.exit_code == 0
