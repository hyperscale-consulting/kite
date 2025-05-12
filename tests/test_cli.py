"""Tests for the CLI module."""

from pathlib import Path
import pytest
from click.testing import CliRunner

from kite.cli import main
from kite.config import Config


@pytest.fixture
def config(tmp_path: Path):
    config = Config(
        management_account_id="111111111111",
        account_ids=["222222222222", "333333333333"],
        active_regions=["us-east-1", "us-west-2", "eu-west-2"],
        role_name="KiteAssessmentRole",
        prowler_output_dir="/tmp/prowler",
        data_dir=str(tmp_path / "test_audit"),
        external_id="123456",
    )
    config_path = tmp_path / "kite.yaml"
    config.save(str(config_path))
    yield config_path
    if config_path.exists():
        config_path.unlink()


@pytest.fixture
def runner():
    runner = CliRunner()
    yield runner


def test_run_list_checks(runner, config):
    result = runner.invoke(main, ["list-checks"])
    assert result.exit_code == 0
