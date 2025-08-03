from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar
from typing import Optional

import click
import yaml


@dataclass
class Config:
    """Configuration class for Kite.

    This class holds the configuration loaded from the YAML file and provides
    global access to the configuration throughout the application.
    """

    management_account_id: str | None
    account_ids: list[str] | None
    active_regions: list[str]
    role_name: str
    prowler_output_dir: Path
    external_id: str
    data_dir: Path = Path(".kite/audit")

    # Class variable to hold the singleton instance
    _instance: ClassVar[Optional["Config"]] = None

    @classmethod
    def create(
        cls,
        management_account_id: str | None,
        account_ids: list[str],
        active_regions: list[str],
        role_name: str,
        prowler_output_dir: Path,
        external_id: str,
        data_dir: Path,
    ):
        cls._instance = cls(
            management_account_id=management_account_id,
            account_ids=account_ids,
            active_regions=active_regions,
            role_name=role_name,
            prowler_output_dir=prowler_output_dir,
            external_id=external_id,
            data_dir=data_dir,
        )
        return cls._instance

    @classmethod
    def get(cls) -> "Config":
        """Get the current configuration instance.

        Returns:
            The current configuration instance.

        Raises:
            RuntimeError: If configuration hasn't been loaded yet.
        """
        if cls._instance is None:
            raise RuntimeError("Configuration not loaded. Call load() first.")
        return cls._instance

    @classmethod
    def load(cls, config_path: str) -> "Config":
        """Load and validate configuration from a YAML file.

        Args:
            config_path: Path to the YAML configuration file.

        Returns:
            A new Config instance.

        Raises:
            ClickException: If the config file is not found or invalid.
        """
        try:
            with open(config_path) as f:
                data = yaml.safe_load(f) or {}

            # Check for required fields
            required_fields = [
                "active_regions",
                "role_name",
                "prowler_output_dir",
                "external_id",
            ]
            missing_fields = [field for field in required_fields if not data.get(field)]

            # Check account field requirements
            has_management_account = bool(data.get("management_account_id"))
            has_account_ids = bool(data.get("account_ids"))

            if not has_management_account and not has_account_ids:
                missing_fields.append("management_account_id or account_ids")

            if missing_fields:
                raise click.ClickException(
                    "Missing required fields in config file: "
                    f"{', '.join(missing_fields)}"
                )

            # Create new instance and store it as the singleton
            cls._instance = cls(
                management_account_id=data.get("management_account_id"),
                account_ids=data.get("account_ids"),
                active_regions=data["active_regions"],
                role_name=data["role_name"],
                prowler_output_dir=Path(data["prowler_output_dir"]),
                external_id=data["external_id"],
                data_dir=Path(data.get("data_dir", ".kite/audit")),
            )
            return cls._instance

        except FileNotFoundError as e:
            raise click.ClickException(f"Config file not found: {config_path}") from e
        except yaml.YAMLError as e:
            raise click.ClickException(f"Error parsing config file: {str(e)}") from e

    def save(self, config_path: str) -> None:
        """Save the current configuration to a YAML file.

        Args:
            config_path: Path to save the YAML configuration file.

        Raises:
            RuntimeError: If configuration hasn't been loaded yet.
            ClickException: If there's an error saving the file.
        """

        try:
            config_dict = {
                "management_account_id": self.management_account_id,
                "account_ids": self.account_ids,
                "active_regions": self.active_regions,
                "role_name": self.role_name,
                "prowler_output_dir": str(self.prowler_output_dir),
                "external_id": self.external_id,
                "data_dir": str(self.data_dir),
            }
            # Remove None values
            config_dict = {k: v for k, v in config_dict.items() if v is not None}

            with open(config_path, "w") as f:
                yaml.dump(config_dict, f, default_flow_style=False)
        except Exception as e:
            raise click.ClickException(f"Error saving config file: {str(e)}") from e
