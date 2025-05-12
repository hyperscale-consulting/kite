"""Data storage and retrieval module for Kite."""

from dataclasses import asdict
import json
import os
from typing import Dict, Any, Optional, List
from datetime import datetime

import click

from kite.config import Config
from kite.models import Organization, DelegatedAdmin, WorkloadResources
from kite.ec2 import EC2Instance


def _save_data(
    data: Dict[str, Any],
    data_type: str,
    account_id: str = "organization"
) -> None:
    """Save data to a file in the data directory.

    Args:
        data: The data to save.
        data_type: The type of data being saved (e.g., 'organization',
            'delegated_admins').
        account_id: The AWS account ID to save the data for. Defaults to
            'organization'.
    """
    # Create data directory if it doesn't exist
    os.makedirs(Config.get().data_dir, exist_ok=True)

    # Create account-specific directory if needed
    account_dir = f"{Config.get().data_dir}/{account_id}"
    os.makedirs(account_dir, exist_ok=True)

    # Save data to file
    file_path = f"{account_dir}/{data_type}.json"
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def _load_data(
    data_type: str,
    account_id: str = "organization"
) -> Optional[Dict[str, Any]]:
    """Load data from a file in the data directory.

    Args:
        data_type: The type of data to load (e.g., 'organization',
            'delegated_admins').
        account_id: The AWS account ID to load the data for. Defaults to
            'organization'.

    Returns:
        The loaded data, or None if the file doesn't exist.
    """
    file_path = f"{Config.get().data_dir}/{account_id}/{data_type}.json"
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def get_organization() -> Optional[Organization]:
    """Get the organization data.

    Returns:
        The organization data, or None if not found.
    """
    data = _load_data("organization")
    if data is None:
        return None
    return Organization.from_dict(data)


def save_organization(org: Organization) -> None:
    """Save the organization data."""
    _save_data(asdict(org), "organization")


def get_delegated_admins() -> Optional[Dict[str, List[DelegatedAdmin]]]:
    """Get the delegated administrators data.

    Returns:
        The delegated administrators data, or None if not found.
    """
    data = _load_data("delegated_admins")
    if data is None:
        return None

    # Convert the JSON data back into DelegatedAdmin objects
    return [DelegatedAdmin.from_dict(admin) for admin in data]


def save_delegated_admins(admins: List[DelegatedAdmin]) -> None:
    """Save delegated administrators data.

    Args:
        admins: The delegated administrators data to save.
    """
    _save_data([asdict(admin) for admin in admins], "delegated_admins")


def save_mgmt_account_workload_resources(resources: WorkloadResources) -> None:
    """Save management account workload resources.

    Args:
        resources: The workload resources to save.
    """
    _save_data(resources.to_dict(), "mgmt_account_workload_resources")


def get_mgmt_account_workload_resources() -> Optional[WorkloadResources]:
    """Get management account workload resources.

    Returns:
        The management account workload resources, or None if not found.
    """
    data = _load_data("mgmt_account_workload_resources")
    if data is None:
        return None
    return WorkloadResources.from_dict(data)


def save_organization_features(features: List[str]) -> None:
    """Save organization features.

    Args:
        features: The list of organization features to save.
    """
    _save_data({"features": features}, "organization_features")


def get_organization_features() -> Optional[List[str]]:
    """Get organization features.

    Returns:
        The list of organization features, or None if not found.
    """
    data = _load_data("organization_features")
    if data is None:
        return None
    return data.get("features", [])


def save_credentials_report(account_id: str, report: Dict[str, Any]) -> None:
    """Save credentials report for an account.

    Args:
        account_id: The AWS account ID to save the report for.
        report: The credentials report data to save.
    """
    _save_data(report, "credentials_report", account_id)


def get_credentials_report(account_id: str) -> Optional[Dict[str, Any]]:
    """Get credentials report for an account.

    Args:
        account_id: The AWS account ID to get the report for.

    Returns:
        The credentials report data, or None if not found.
    """
    return _load_data("credentials_report", account_id)


def save_account_summary(account_id: str, summary: Dict[str, Any]) -> None:
    """Save account summary for an account.

    Args:
        account_id: The AWS account ID to save the summary for.
        summary: The account summary data to save.
    """
    _save_data(summary, "account_summary", account_id)


def get_account_summary(account_id: str) -> Optional[Dict[str, Any]]:
    """Get account summary for an account.

    Args:
        account_id: The AWS account ID to get the summary for.

    Returns:
        The account summary data, or None if not found.
    """
    return _load_data("account_summary", account_id)


def save_saml_providers(providers: List[Dict[str, Any]]) -> None:
    """Save SAML providers.

    Args:
        providers: The list of SAML providers to save.
    """
    _save_data({"providers": providers}, "saml_providers")


def get_saml_providers() -> Optional[List[Dict[str, Any]]]:
    """Get SAML providers.

    Returns:
        The list of SAML providers, or None if not found.
    """
    data = _load_data("saml_providers")
    if data is None:
        return None
    return data.get("providers", [])


def save_oidc_providers(providers: List[Dict[str, Any]]) -> None:
    """Save OIDC providers.

    Args:
        providers: The list of OIDC providers to save.
    """
    _save_data({"providers": providers}, "oidc_providers")


def get_oidc_providers() -> Optional[List[Dict[str, Any]]]:
    """Get OIDC providers.

    Returns:
        The list of OIDC providers, or None if not found.
    """
    data = _load_data("oidc_providers")
    if data is None:
        return None
    return data.get("providers", [])


def save_identity_center_instances(instances: List[Dict[str, Any]]) -> None:
    """Save Identity Center instances.

    Args:
        instances: The list of Identity Center instances to save.
    """
    _save_data({"instances": instances}, "identity_center_instances")


def get_identity_center_instances() -> Optional[List[Dict[str, Any]]]:
    """Get Identity Center instances.

    Returns:
        The list of Identity Center instances, or None if not found.
    """
    data = _load_data("identity_center_instances")
    if data is None:
        return None
    return data.get("instances", [])


def save_ec2_instances(account_id: str, instances: List[EC2Instance]) -> None:
    """Save EC2 instances for an account.

    Args:
        account_id: The AWS account ID to save the instances for.
        instances: The list of EC2 instances to save.
    """
    _save_data([asdict(instance) for instance in instances],
               "ec2_instances", account_id)


def get_ec2_instances(account_id: str) -> Optional[List[Dict[str, Any]]]:
    """Get EC2 instances for an account.

    Args:
        account_id: The AWS account ID to get the instances for.

    Returns:
        The list of EC2 instances, or None if not found.
    """
    data = _load_data("ec2_instances", account_id)
    if data is None:
        return None
    return [EC2Instance.from_dict(instance) for instance in data]


def save_collection_metadata() -> None:
    """Save metadata about the last data collection run."""
    metadata = {
        "timestamp": datetime.now().isoformat(),
        "external_id": Config.get().external_id,
    }
    _save_data(metadata, "collection_metadata")


def get_collection_metadata() -> Optional[Dict[str, Any]]:
    """Get metadata about the last data collection run.

    Returns:
        The collection metadata, or None if not found.
    """
    return _load_data("collection_metadata")


def verify_collection_status() -> None:
    """Verify that data collection has been run and external ID matches.

    Raises:
        ClickException: If collection hasn't been run or external ID doesn't match.
    """
    metadata = get_collection_metadata()
    if not metadata:
        raise click.ClickException(
            "Data collection has not been run. Please run 'kite collect' first."
        )

    current_external_id = Config.get().external_id
    if metadata["external_id"] != current_external_id:
        raise click.ClickException(
            "External ID has changed since last data collection. "
            "Please run 'kite collect' again."
        )
