"""Tests for the CLI module."""

from pathlib import Path
from typing import Generator
import pytest
import yaml
from unittest.mock import patch
from click.testing import CliRunner

from kite.cli import main
from kite.config import Config


@pytest.fixture(autouse=True)
def clear_config():
    """Clear the Config singleton between tests."""
    Config._instance = None
    yield


@pytest.fixture
def mock_check_themes():
    """Replace real CHECK_THEMES with a mock version that uses stub functions."""

    # Create stub functions that return predefined responses
    def stub_check_aws_organizations_usage():
        return {
            "check_id": "aws-organizations-usage",
            "check_name": "AWS Organizations Usage",
            "status": "PASS",
            "details": {
                "master_account_id": "111111111111",
                "arn": "arn:aws:organizations::111111111111:organization/o-example123",
                "feature_set": "ALL",
                "message": "AWS Organizations is being used for account management.",
            },
        }

    def stub_check_account_separation():
        return {
            "check_id": "acc-001",
            "check_name": "Account Separation",
            "status": "PASS",
            "details": {
                "message": "Accounts are properly separated.",
            },
        }

    def stub_check_ou_structure():
        return {
            "check_id": "ou-001",
            "check_name": "OU Structure",
            "status": "PASS",
            "details": {
                "message": "OU structure follows best practices.",
            },
        }

    # Create mock CHECK_THEMES dictionary
    mock_themes = {
        "Multi-Account Architecture": {
            "description": (
                "Checks related to AWS Organizations structure and multi-account setup"
            ),
            "checks": [
                stub_check_aws_organizations_usage,
                stub_check_account_separation,
                stub_check_ou_structure,
            ],
        },
        "Root User Security": {
            "description": "Checks related to root user security and access controls",
            "checks": [],  # Empty list for this test
        },
    }

    # Patch the CHECK_THEMES dictionary
    with patch("kite.cli.CHECK_THEMES", mock_themes):
        yield


@pytest.fixture
def valid_config(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary valid config file."""
    config = {
        "management_account_id": "111111111111",
        "account_ids": ["222222222222", "333333333333"],
        "active_regions": ["us-east-1", "us-west-2", "eu-west-2"],
        "role_name": "KiteAssessmentRole",
        "prowler_output_dir": "/tmp/prowler",
    }
    config_path = tmp_path / "kite.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f)
    yield config_path
    if config_path.exists():
        config_path.unlink()


@pytest.fixture
def valid_config_without_account_ids(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary valid config file without account_ids."""
    config = {
        "management_account_id": "111111111111",
        "active_regions": ["us-east-1", "us-west-2", "eu-west-2"],
        "role_name": "KiteAssessmentRole",
        "prowler_output_dir": "/tmp/prowler",
    }
    config_path = tmp_path / "kite.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f)
    yield config_path
    if config_path.exists():
        config_path.unlink()


@pytest.fixture
def valid_config_with_account_ids_only(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary valid config file with only account_ids."""
    config = {
        "account_ids": ["222222222222", "333333333333"],
        "active_regions": ["us-east-1", "us-west-2", "eu-west-2"],
        "role_name": "KiteAssessmentRole",
        "prowler_output_dir": "/tmp/prowler",
    }
    config_path = tmp_path / "kite.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f)
    yield config_path
    if config_path.exists():
        config_path.unlink()


def test_start_command_with_management_account(valid_config: Path, mock_check_themes):
    """Test the start command with a valid config file containing a management
    account."""
    runner = CliRunner()
    result = runner.invoke(main, ["start", "--config", str(valid_config)])

    assert result.exit_code == 0
    assert "Starting AWS security assessment" in result.output
    assert "Management Account: 111111111111" in result.output
    assert "Target Accounts: 222222222222, 333333333333" in result.output
    assert "Regions: us-east-1, us-west-2, eu-west-2" in result.output
    assert "Role Name: KiteAssessmentRole" in result.output
    assert "AWS Organizations Usage" in result.output
    assert "Account Separation" in result.output
    assert "OU Structure" in result.output
    assert "Assessment results saved to kite-results.yaml" in result.output


def test_start_command_without_account_ids(
    valid_config_without_account_ids: Path, mock_check_themes
):
    """Test the start command with a valid config file without account_ids."""
    runner = CliRunner()
    result = runner.invoke(
        main, ["start", "--config", str(valid_config_without_account_ids)]
    )

    assert result.exit_code == 0
    assert "Starting AWS security assessment" in result.output
    assert "Management Account: 111111111111" in result.output
    assert "Target Accounts: ALL" in result.output
    assert "Regions: us-east-1, us-west-2, eu-west-2" in result.output
    assert "Role Name: KiteAssessmentRole" in result.output
    assert "Assessment results saved to kite-results.yaml" in result.output


def test_start_command_with_account_ids_only(
    valid_config_with_account_ids_only: Path, mock_check_themes
):
    """Test the start command with a valid config file with only account_ids."""
    runner = CliRunner()
    result = runner.invoke(
        main, ["start", "--config", str(valid_config_with_account_ids_only)]
    )

    assert result.exit_code == 0
    assert "Starting AWS security assessment" in result.output
    assert "Target Accounts: 222222222222, 333333333333" in result.output
    assert "Regions: us-east-1, us-west-2, eu-west-2" in result.output
    assert "Role Name: KiteAssessmentRole" in result.output
    assert "Assessment results saved to kite-results.yaml" in result.output
