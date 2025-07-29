"""Tests for the config module."""

from collections.abc import Generator
from pathlib import Path

import pytest
import yaml
from click.exceptions import ClickException

from hyperscale.kite.config import Config


@pytest.fixture(autouse=True)
def clear_config():
    """Clear the Config singleton between tests."""
    Config._instance = None
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
        "external_id": "123456",
    }
    config_path = tmp_path / "kite.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f)
    yield config_path
    if config_path.exists():
        config_path.unlink()


@pytest.fixture
def invalid_config(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary invalid config file."""
    config = {
        # Missing management_account_id, active_regions, and external_id
        "some_other_field": "value",
        "role_name": "KiteAssessmentRole",
        "prowler_output_dir": "/tmp/prowler",
    }
    config_path = tmp_path / "invalid_kite.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f)
    yield config_path
    if config_path.exists():
        config_path.unlink()


@pytest.fixture
def empty_config(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary empty config file."""
    config_path = tmp_path / "empty_kite.yaml"
    with open(config_path, "w") as f:
        f.write("")
    yield config_path
    if config_path.exists():
        config_path.unlink()


@pytest.fixture
def malformed_config(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary malformed YAML config file."""
    config_path = tmp_path / "malformed_kite.yaml"
    with open(config_path, "w") as f:
        f.write("this is not valid yaml: {")
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
        "external_id": "123456",
    }
    config_path = tmp_path / "kite_no_accounts.yaml"
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
        "external_id": "123456",
    }
    config_path = tmp_path / "kite_account_ids.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f)
    yield config_path
    if config_path.exists():
        config_path.unlink()


@pytest.fixture
def invalid_config_missing_both(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary invalid config file missing both account fields."""
    config = {
        "active_regions": ["us-east-1", "us-west-2", "eu-west-2"],
        "role_name": "KiteAssessmentRole",
        "prowler_output_dir": "/tmp/prowler",
        "external_id": "123456",
    }
    config_path = tmp_path / "invalid_kite.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f)
    yield config_path
    if config_path.exists():
        config_path.unlink()


def test_load_valid_config(valid_config: Path):
    """Test loading a valid config file."""
    config = Config.load(str(valid_config))
    assert config.management_account_id == "111111111111"
    assert config.account_ids == ["222222222222", "333333333333"]
    assert config.active_regions == ["us-east-1", "us-west-2", "eu-west-2"]


def test_load_nonexistent_config():
    """Test loading a nonexistent config file."""
    with pytest.raises(ClickException) as exc_info:
        Config.load("nonexistent.yaml")
    assert "Config file not found" in str(exc_info.value)


def test_load_invalid_config(invalid_config: Path):
    """Test loading an invalid config file with missing required fields."""
    with pytest.raises(ClickException) as exc_info:
        Config.load(str(invalid_config))
    assert "Missing required fields in config file" in str(exc_info.value)
    assert "account_ids" in str(exc_info.value)
    assert "active_regions" in str(exc_info.value)


def test_load_empty_config(empty_config: Path):
    """Test loading an empty config file."""
    with pytest.raises(ClickException) as exc_info:
        Config.load(str(empty_config))
    assert "Missing required fields in config file" in str(exc_info.value)
    assert "management_account_id" in str(exc_info.value)
    assert "account_ids" in str(exc_info.value)
    assert "active_regions" in str(exc_info.value)


def test_load_malformed_config(malformed_config: Path):
    """Test loading a malformed YAML config file."""
    with pytest.raises(ClickException) as exc_info:
        Config.load(str(malformed_config))
    assert "Error parsing config file" in str(exc_info.value)


def test_get_without_loading():
    """Test getting config before loading it."""
    with pytest.raises(RuntimeError) as exc_info:
        Config.get()
    assert "Configuration not loaded" in str(exc_info.value)


def test_singleton_pattern(valid_config: Path):
    """Test that the Config class maintains a single instance."""
    config1 = Config.load(str(valid_config))
    config2 = Config.get()
    assert config1 is config2  # Same instance


def test_load_valid_config_without_account_ids(valid_config_without_account_ids: Path):
    """Test loading a valid config file without account_ids."""
    config = Config.load(str(valid_config_without_account_ids))
    assert config.management_account_id == "111111111111"
    assert config.account_ids is None
    assert config.active_regions == ["us-east-1", "us-west-2", "eu-west-2"]


def test_missing_management_account(
    invalid_config: Path,
):
    """
    Test loading an invalid config file with missing
    management_account_id.
    """
    with pytest.raises(ClickException) as exc_info:
        Config.load(str(invalid_config))
    error_msg = str(exc_info.value)
    assert "Missing required fields" in error_msg
    assert "in config file" in error_msg
    assert "management_account_id" in error_msg
    assert "active_regions" in error_msg


def test_load_valid_config_with_account_ids_only(
    valid_config_with_account_ids_only: Path,
):
    """Test loading a valid config file with only account_ids."""
    config = Config.load(str(valid_config_with_account_ids_only))
    assert config.management_account_id is None
    assert config.account_ids == ["222222222222", "333333333333"]
    assert config.active_regions == ["us-east-1", "us-west-2", "eu-west-2"]


def test_load_invalid_config_missing_both_account_fields(
    invalid_config_missing_both: Path,
):
    """Test loading an invalid config file missing both account fields."""
    with pytest.raises(ClickException) as exc_info:
        Config.load(str(invalid_config_missing_both))
    error_msg = str(exc_info.value)
    assert "Missing required fields in config file" in error_msg
    assert "management_account_id or account_ids" in error_msg
