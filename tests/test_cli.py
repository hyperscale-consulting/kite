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
def runner(
    monkeypatch,
    config,
    organization,
    delegated_admins,
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
    monkeypatch.setattr(kms, "get_customer_keys", lambda *args, **kwargs: [])
    monkeypatch.setattr(s3, "get_buckets", lambda *args, **kwargs: [])
    monkeypatch.setattr(cloudfront, "get_distributions", lambda *args, **kwargs: [])
    monkeypatch.setattr(iam, "fetch_organization_features", lambda *args, **kwargs: [])
    monkeypatch.setattr(iam, "fetch_credentials_report", lambda *args, **kwargs: [])
    monkeypatch.setattr(iam, "fetch_account_summary", lambda *args, **kwargs: [])
    monkeypatch.setattr(iam, "list_saml_providers", lambda *args, **kwargs: [])
    monkeypatch.setattr(iam, "list_oidc_providers", lambda *args, **kwargs: [])
    monkeypatch.setattr(identity_center, "list_identity_center_instances",
                        lambda *args, **kwargs: [])
    runner = CliRunner()
    with runner.isolated_filesystem():
        yield runner


def test_run_list_checks(runner, config):
    result = runner.invoke(main, ["list-checks"])
    assert result.exit_code == 0


def test_run_start_without_collect(runner, config_path):
    result = runner.invoke(main, ["start", "--config", str(config_path)])
    assert result.exit_code != 0
    assert (
        "Data collection has not been run. Please run 'kite collect' first."
        in result.output
    )


def test_run_collect(runner, config_path):
    result = runner.invoke(main, ["collect", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "Data collection complete" in result.output
