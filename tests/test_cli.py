from pathlib import Path

import pytest
from click.testing import CliRunner
from prompt_toolkit import PromptSession
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from hyperscale.kite import cloudfront
from hyperscale.kite import dynamodb
from hyperscale.kite import ec2
from hyperscale.kite import ecs
from hyperscale.kite import eks
from hyperscale.kite import iam
from hyperscale.kite import kms
from hyperscale.kite import lambda_
from hyperscale.kite import rds
from hyperscale.kite import redshift
from hyperscale.kite import s3
from hyperscale.kite import sagemaker
from hyperscale.kite import sns
from hyperscale.kite import sqs
from hyperscale.kite import sts
from hyperscale.kite.cli import Assessment
from hyperscale.kite.cli import main
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_organization
from tests.clients import OrganizationsClient
from tests.factories import create_config


@pytest.fixture
def config_path(tmp_path: Path, config: Config):
    path = tmp_path / "kite.yaml"
    config.save(path)
    yield path
    if path.exists():
        path.unlink()


@pytest.fixture
def ec2_instances():
    yield [
        {
            "InstanceId": "i-1234567890abcdef0",
            "InstanceType": "t2.micro",
            "State": {"Name": "running"},
        }
    ]


@pytest.fixture
def organization_features():
    yield {"features": ["RootSessions", "RootCredentialsManagement"]}


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
            },
        ],
    }


@pytest.fixture
def account_summary():
    yield {
        "AccountMFAEnabled": 1,
        "AccountAccessKeysPresent": 0,
    }


@pytest.fixture
def virtual_mfa_devices():
    return [
        {
            "SerialNumber": "arn:aws:iam::123456789012:mfa/root",
            "User": {"Arn": "arn:aws:iam::123456789012:root"},
        },
        {
            "SerialNumber": "arn:aws:iam::123456789012:mfa/user1",
            "User": {"Arn": "arn:aws:iam::123456789012:user/user1"},
        },
    ]


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
def runner(
    monkeypatch,
    stub_aws_session,
    account_summary,
    credentials_report,
    virtual_mfa_devices,
    password_policy,
    organization_features,
    ec2_instances,
):
    def mock_assume_role(*_):
        return stub_aws_session

    monkeypatch.setattr(sts, "assume_role", mock_assume_role)

    monkeypatch.setattr(ec2, "get_running_instances", lambda *_: ec2_instances)
    monkeypatch.setattr(ecs, "get_clusters", lambda *_: [])
    monkeypatch.setattr(eks, "get_cluster_names", lambda *_: [])
    monkeypatch.setattr(lambda_, "get_functions", lambda *_: [])
    monkeypatch.setattr(rds, "get_instances", lambda *_: [])
    monkeypatch.setattr(dynamodb, "get_tables", lambda *_: [])
    monkeypatch.setattr(redshift, "get_clusters", lambda *_: [])
    monkeypatch.setattr(sagemaker, "get_notebook_instances", lambda *_: [])
    monkeypatch.setattr(sns, "get_topics", lambda *_: [])
    monkeypatch.setattr(sqs, "get_queues", lambda *_: [])
    monkeypatch.setattr(kms, "get_keys", lambda *_: [])
    monkeypatch.setattr(s3, "get_bucket_names", lambda *_: [])
    monkeypatch.setattr(s3, "get_buckets", lambda *_: [])
    monkeypatch.setattr(cloudfront, "get_distributions", lambda *_: [])
    monkeypatch.setattr(iam, "fetch_credentials_report", lambda *_: credentials_report)
    monkeypatch.setattr(iam, "fetch_account_summary", lambda *_: account_summary)
    monkeypatch.setattr(iam, "list_saml_providers", lambda *_: [])
    monkeypatch.setattr(iam, "list_oidc_providers", lambda *_: [])
    monkeypatch.setattr(
        iam, "fetch_virtual_mfa_devices", lambda *_: virtual_mfa_devices
    )
    monkeypatch.setattr(
        iam, "fetch_organization_features", lambda *_: organization_features
    )
    monkeypatch.setattr(iam, "get_password_policy", lambda *_: password_policy)
    runner = CliRunner()
    with runner.isolated_filesystem():
        yield runner


def test_run_list_checks(runner):
    create_config()
    result = runner.invoke(main, ["list-checks"])
    assert result.exit_code == 0


def test_run_assess_without_collect(runner, config_path):
    result = runner.invoke(main, ["assess", "--config", str(config_path)])
    assert (
        "Data collection has not been run. Please run 'kite collect' first."
        in result.output
    )
    assert result.exit_code != 0


def test_run_collect(runner, stub_aws_session, tmp_path):
    mgmt_account_id = "111111111111"
    audit_account_id = "999999999999"

    org_client = OrganizationsClient()
    org_client.set_organization(
        id="test-org", master_account_id=mgmt_account_id, feature_set="ALL"
    )
    org_client.set_root()
    org_client.add_delegated_admin(audit_account_id, "securityhub.amazonaws.com")

    stub_aws_session.register_client(org_client, "organizations")
    config = create_config(mgmt_account_id=mgmt_account_id)

    result = runner.invoke(
        main, ["collect", "--config", config.save(tmp_path / "kite.yaml")]
    )
    print(result.output)
    assert "Data collection complete" in result.output
    assert result.exit_code == 0
    saved_org = get_organization()
    assert saved_org is not None
    assert saved_org.id == "test-org"
    assert saved_org.master_account_id == mgmt_account_id


@pytest.fixture
def base_path():
    yield Path(__file__).parent


def test_run_assess_without_prowler_output(runner, tmp_path, base_path):
    config = create_config(
        prowler_output_dir=tmp_path / "prowler",  # no prowler data
        data_dir=base_path / "fixtures/audit",  # simulate `collect` has been run
        external_id="123456",  # external_id for simulated `collect`
    )
    config_path = config.save(tmp_path / "kite.yaml")
    result = runner.invoke(main, ["assess", "--config", config_path])
    print(result.output)
    assert result.exit_code != 0
    assert "No Prowler results found" in result.output


def test_run_assess(runner, tmp_path, monkeypatch, base_path):
    config = Config.create(
        management_account_id="111111111111",
        account_ids=[],
        active_regions=["us-west-2", "us-east-1", "eu-west-2"],
        role_name="Kite",
        prowler_output_dir=base_path / "fixtures/prowler",
        data_dir=base_path / "fixtures/audit",
        external_id="123456",
    )
    config_path = config.save(tmp_path / "kite.yaml")

    def responses():
        answer = True
        while True:
            if answer:
                yield "y\n"
            else:
                yield "Because reasons...\n"
            answer = not answer

    with create_pipe_input() as pipe_input:
        test_session = PromptSession(input=pipe_input, output=DummyOutput())
        monkeypatch.setattr("hyperscale.kite.ui.prompt_session", test_session)
        monkeypatch.setattr("hyperscale.kite.ui.confirm_session", test_session)

        for _ in range(500):
            pipe_input.send_text(next(responses()))

        result = runner.invoke(
            main,
            ["assess", "--config", config_path, "--no-auto-save"],
        )
        print(result.output)
        assert result.exit_code == 0
        assessment = Assessment.load()
        assert assessment is not None
        assert assessment.get_finding("root-account-monitoring")["status"] == "PASS"
        assert assessment.get_finding("root-actions-disallowed")["status"] == "FAIL"
        assert (
            assessment.get_finding("no-permissive-role-assumption")["status"] == "PASS"
        )


def test_report_without_results(runner, tmp_path):
    config = create_config()
    result = runner.invoke(main, ["report", "-c", config.save(tmp_path / "kite.yaml")])
    assert result.exit_code != 0
    assert "Results file not found" in result.output


def test_report(runner, tmp_path):
    config = create_config()
    assessment = Assessment()
    assessment.record(
        "Identity and Access Management",
        {
            "check_id": "test_001",
            "check_name": "Test Check 1",
            "description": "A test check for IAM",
            "status": "PASS",
            "reason": "Test passed successfully",
            "details": {"message": "Test passed successfully"},
        },
    )
    assessment.record(
        "Data Protection",
        {
            "check_id": "test_002",
            "check_name": "Test Check 2",
            "description": "A test check for data protection",
            "status": "FAIL",
            "reason": "Test failed as expected",
            "details": {"message": "Test failed as expected"},
        },
    )
    assessment.save()
    result = runner.invoke(main, ["report", "-c", config.save(tmp_path / "kite.yaml")])

    assert "HTML report generated" in result.output
    assert result.exit_code == 0

    report_dir = config.data_dir / "html"
    assert report_dir.exists()
    assert (report_dir / "report.html").exists()
    assert (report_dir / "styles.css").exists()
    assert (report_dir / "script.js").exists()

    # Check the HTML content
    html_content = (report_dir / "report.html").read_text()
    assert "Kite Security Assessment Report" in html_content
    assert "Test Check 1" in html_content
    assert "Test Check 2" in html_content
    assert "PASS" in html_content
    assert "FAIL" in html_content
