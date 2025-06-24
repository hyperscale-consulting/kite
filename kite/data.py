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


def save_saml_providers(providers: List[Dict[str, Any]], account_id: str = "organization") -> None:
    """Save SAML providers.

    Args:
        providers: The list of SAML providers to save.
        account_id: The AWS account ID to save the providers for.
    """
    _save_data({"providers": providers}, "saml_providers", account_id)


def get_saml_providers(account_id: str = "organization") -> Optional[List[Dict[str, Any]]]:
    """Get SAML providers.

    Returns:
        The list of SAML providers, or None if not found.
    """
    data = _load_data("saml_providers", account_id)
    if data is None:
        return None
    return data.get("providers", [])


def save_oidc_providers(providers: List[Dict[str, Any]], account_id: str = "organization") -> None:
    """Save OIDC providers.

    Args:
        providers: The list of OIDC providers to save.
        account_id: The AWS account ID to save the providers for.
    """
    _save_data({"providers": providers}, "oidc_providers", account_id)


def get_oidc_providers(account_id: str = "organization") -> Optional[List[Dict[str, Any]]]:
    """Get OIDC providers.

    Returns:
        The list of OIDC providers, or None if not found.
    """
    data = _load_data("oidc_providers", account_id)
    if data is None:
        return None
    return data.get("providers", [])


def save_identity_center_instances(instances: List[Dict[str, Any]], account_id: str = "organization") -> None:
    """Save Identity Center instances.

    Args:
        instances: The list of Identity Center instances to save.
        account_id: The AWS account ID to save the instances for.
    """
    _save_data({"instances": instances}, "identity_center_instances", account_id)


def get_identity_center_instances(account_id: str = "organization") -> Optional[List[Dict[str, Any]]]:
    """Get Identity Center instances.

    Returns:
        The list of Identity Center instances, or None if not found.
    """
    data = _load_data("identity_center_instances", account_id)
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


def save_virtual_mfa_devices(account_id: str, devices: List[Dict[str, Any]]) -> None:
    """
    Save virtual MFA devices for an account.

    Args:
        account_id: The AWS account ID.
        devices: List of virtual MFA device information.
    """
    _save_data(devices, "virtual_mfa_devices", account_id)


def get_virtual_mfa_devices(account_id: str) -> List[Dict[str, Any]]:
    """
    Get virtual MFA devices for an account.

    Args:
        account_id: The AWS account ID.

    Returns:
        List of virtual MFA device information.
    """
    return _load_data("virtual_mfa_devices", account_id)


def save_password_policy(account_id: str, policy: Dict[str, Any]) -> None:
    """
    Save password policy for an account.

    Args:
        account_id: The AWS account ID to save the policy for.
        policy: The password policy data to save.
    """
    _save_data(policy, "password_policy", account_id)


def get_password_policy(account_id: str) -> Optional[Dict[str, Any]]:
    """
    Get password policy for an account.

    Args:
        account_id: The AWS account ID to get the policy for.

    Returns:
        The password policy data, or None if not found.
    """
    return _load_data("password_policy", account_id)


def save_cognito_user_pools(account_id: str, pools: List[Dict[str, Any]]) -> None:
    """
    Save Cognito user pools for an account.

    Args:
        account_id: The AWS account ID to save the pools for.
        pools: The list of Cognito user pools to save.
    """
    _save_data(pools, "cognito_user_pools", account_id)


def save_cognito_user_pool(
    account_id: str,
    user_pool_id: str,
    pool_data: Dict[str, Any]
) -> None:
    """
    Save details for a specific Cognito user pool.

    Args:
        account_id: The AWS account ID.
        user_pool_id: The ID of the Cognito user pool.
        pool_data: The user pool data to save.
    """
    _save_data(pool_data, f"cognito_user_pool_{user_pool_id}", account_id)


def get_cognito_user_pools(account_id: str) -> List[Dict[str, Any]]:
    """
    Get Cognito user pools for an account.

    Args:
        account_id: The AWS account ID to get the pools for.

    Returns:
        List of dictionaries containing user pool information, or empty list.
    """
    return _load_data("cognito_user_pools", account_id) or []


def get_cognito_user_pool(account_id: str, user_pool_id: str) -> Dict[str, Any]:
    """
    Get details for a specific Cognito user pool.

    Args:
        account_id: The AWS account ID.
        user_pool_id: The ID of the Cognito user pool.

    Returns:
        Dictionary containing the user pool information, or empty dict if not found.
    """
    return _load_data(f"cognito_user_pool_{user_pool_id}", account_id) or {}


def save_key_pairs(account_id: str, key_pairs: List[Dict[str, Any]]) -> None:
    """
    Save EC2 key pairs for an account.

    Args:
        account_id: The AWS account ID to save the key pairs for.
        key_pairs: The list of EC2 key pairs to save.
    """
    _save_data(key_pairs, "ec2_key_pairs", account_id)


def get_key_pairs(account_id: str) -> List[Dict[str, Any]]:
    """
    Get EC2 key pairs for an account.

    Args:
        account_id: The AWS account ID to get the key pairs for.

    Returns:
        List of dictionaries containing key pair information, or empty list.
    """
    return _load_data("ec2_key_pairs", account_id) or []


def save_secrets(account_id: str, region: str, secrets: List[Dict[str, Any]]) -> None:
    """
    Save Secrets Manager secrets for an account and region.

    Args:
        account_id: The AWS account ID to save the secrets for.
        region: The AWS region to save the secrets for.
        secrets: The list of secrets to save.
    """
    _save_data(secrets, f"secrets_{region}", account_id)


def get_secrets(account_id: str, region: str) -> List[Dict[str, Any]]:
    """
    Get Secrets Manager secrets for an account and region.

    Args:
        account_id: The AWS account ID to get the secrets for.
        region: The AWS region to get the secrets for.

    Returns:
        List of dictionaries containing secret information, or empty list.
    """
    return _load_data(f"secrets_{region}", account_id) or []


def save_roles(account_id: str, roles: List[Dict[str, Any]]) -> None:
    """
    Save IAM roles for an account.

    Args:
        account_id: The AWS account ID to save the roles for.
        roles: The list of IAM roles to save.
    """
    _save_data(roles, "iam_roles", account_id)


def get_roles(account_id: str) -> List[Dict[str, Any]]:
    """
    Get IAM roles for an account.

    Args:
        account_id: The AWS account ID to get the roles for.

    Returns:
        List of dictionaries containing role information, or empty list.
    """
    return _load_data("iam_roles", account_id) or []


def save_inline_policy_document(account_id: str, role_name: str, policy_name: str, policy_document: Dict[str, Any]) -> None:
    """
    Save an inline policy document for a role.

    Args:
        account_id: The AWS account ID.
        role_name: The name of the IAM role.
        policy_name: The name of the inline policy.
        policy_document: The inline policy document to save.
    """
    data = {
        "RoleName": role_name,
        "PolicyName": policy_name,
        "PolicyDocument": policy_document
    }
    _save_data(data, f"inline_policy_{role_name}_{policy_name}", account_id)


def get_inline_policy_document(account_id: str, role_name: str, policy_name: str) -> Dict[str, Any]:
    """
    Get an inline policy document for a role.

    Args:
        account_id: The AWS account ID.
        role_name: The name of the IAM role.
        policy_name: The name of the inline policy.

    Returns:
        Dictionary containing the inline policy document, or empty dict.
    """
    return _load_data(f"inline_policy_{role_name}_{policy_name}", account_id) or {}


def save_customer_managed_policies(account_id: str, policies: List[Dict[str, Any]]) -> None:
    """
    Save customer managed policies for an account.

    Args:
        account_id: The AWS account ID to save the policies for.
        policies: The list of customer managed policies to save.
    """
    _save_data(policies, "customer_managed_policies", account_id)


def get_customer_managed_policies(account_id: str) -> List[Dict[str, Any]]:
    """
    Get customer managed policies for an account.

    Args:
        account_id: The AWS account ID to get the policies for.

    Returns:
        List of dictionaries containing policy information, or empty list.
    """
    return _load_data("customer_managed_policies", account_id) or []


def save_policy_document(account_id: str, policy_arn: str, policy_document: Dict[str, Any]) -> None:
    """
    Save a policy document for a customer managed policy.

    Args:
        account_id: The AWS account ID.
        policy_arn: The ARN of the customer managed policy.
        policy_document: The policy document to save.
    """
    # Convert the ARN to a safe string for file name
    safe_arn = policy_arn.replace("/", "_").replace(":", "_")
    _save_data(policy_document, f"policy_document_{safe_arn}", account_id)


def get_policy_document(account_id: str, policy_arn: str) -> Dict[str, Any]:
    """
    Get a policy document for a customer managed policy.

    Args:
        account_id: The AWS account ID.
        policy_arn: The ARN of the customer managed policy.

    Returns:
        Dictionary containing the policy document, or empty dict.
    """
    # Convert the ARN to a safe string for file name
    safe_arn = policy_arn.replace("/", "_").replace(":", "_")
    return _load_data(f"policy_document_{safe_arn}", account_id) or {}


def save_bucket_metadata(account_id: str, buckets: List[Dict[str, Any]]) -> None:
    """
    Save S3 bucket metadata for an account.

    Args:
        account_id: The AWS account ID to save the metadata for.
        buckets: The list of S3 buckets with their policies.
    """
    _save_data(buckets, "bucket_metadata", account_id)


def get_bucket_metadata(account_id: str) -> List[Dict[str, Any]]:
    """
    Get S3 bucket metadata for an account.

    Args:
        account_id: The AWS account ID to get the metadata for.

    Returns:
        List of dictionaries containing bucket information and policies.
    """
    return _load_data("bucket_metadata", account_id) or []


def save_sns_topics(account_id: str, region: str, topics: List[Dict[str, Any]]) -> None:
    """Save SNS topics for an account and region.

    Args:
        account_id: The AWS account ID to save the topics for.
        region: The AWS region to save the topics for.
        topics: The list of SNS topics to save.
    """
    _save_data({"topics": topics}, f"sns_topics_{region}", account_id)


def get_sns_topics(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get SNS topics for an account and region.

    Args:
        account_id: The AWS account ID to get the topics for.
        region: The AWS region to get the topics for.

    Returns:
        The list of SNS topics, or an empty list if not found.
    """
    data = _load_data(f"sns_topics_{region}", account_id)
    if data is None:
        return []
    return data.get("topics", [])


def save_sqs_queues(account_id: str, region: str, queues: List[Dict[str, Any]]) -> None:
    """Save SQS queues for an account and region.

    Args:
        account_id: The AWS account ID to save the queues for.
        region: The AWS region to save the queues for.
        queues: The list of SQS queues to save.
    """
    _save_data({"queues": queues}, f"sqs_queues_{region}", account_id)


def get_sqs_queues(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get SQS queues for an account and region.

    Args:
        account_id: The AWS account ID to get the queues for.
        region: The AWS region to get the queues for.

    Returns:
        The list of SQS queues, or an empty list if not found.
    """
    data = _load_data(f"sqs_queues_{region}", account_id)
    if data is None:
        return []
    return data.get("queues", [])


def save_lambda_functions(account_id: str, region: str, functions: List[Dict[str, Any]]) -> None:
    """Save Lambda functions for an account and region.

    Args:
        account_id: The AWS account ID to save the functions for.
        region: The AWS region to save the functions for.
        functions: The list of Lambda functions to save.
    """
    _save_data({"functions": functions}, f"lambda_functions_{region}", account_id)


def get_lambda_functions(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Lambda functions for an account and region.

    Args:
        account_id: The AWS account ID to get the functions for.
        region: The AWS region to get the functions for.

    Returns:
        The list of Lambda functions, or an empty list if not found.
    """
    data = _load_data(f"lambda_functions_{region}", account_id)
    if data is None:
        return []
    return data.get("functions", [])


def save_kms_keys(account_id: str, region: str, keys: List[Dict[str, Any]]) -> None:
    """Save KMS keys for an account and region.

    Args:
        account_id: The AWS account ID to save the keys for.
        region: The AWS region to save the keys for.
        keys: The list of KMS keys to save.
    """
    _save_data({"keys": keys}, f"kms_keys_{region}", account_id)


def get_kms_keys(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get KMS keys for an account and region.

    Args:
        account_id: The AWS account ID to get the keys for.
        region: The AWS region to get the keys for.

    Returns:
        The list of KMS keys, or an empty list if not found.
    """
    data = _load_data(f"kms_keys_{region}", account_id)
    if data is None:
        return []
    return data.get("keys", [])


def save_identity_center_permission_sets(account_id: str, instance_id: str, permission_sets: List[Dict[str, Any]]) -> None:
    """Save Identity Center permission sets for an account and instance.

    Args:
        account_id: The AWS account ID.
        instance_id: The ID of the Identity Center instance.
        permission_sets: The list of permission sets to save.
    """
    _save_data({"permission_sets": permission_sets}, f"identity_center_permission_sets_{instance_id}", account_id)


def get_identity_center_permission_sets(account_id: str, instance_id: str) -> List[Dict[str, Any]]:
    """Get Identity Center permission sets for an account and instance.

    Args:
        account_id: The AWS account ID.
        instance_id: The ID of the Identity Center instance.

    Returns:
        The list of Identity Center permission sets, or an empty list if not found.
    """
    data = _load_data(f"identity_center_permission_sets_{instance_id}", account_id)
    if data is None:
        return []
    return data.get("permission_sets", [])


def save_identity_store_users(account_id: str, instance_id: str, users: List[Dict[str, Any]]) -> None:
    """Save Identity Store users for an account and instance.

    Args:
        account_id: The AWS account ID.
        instance_id: The ID of the Identity Center instance.
        users: The list of users to save.
    """
    _save_data({"users": users}, f"identity_store_users_{instance_id}", account_id)


def get_identity_store_users(account_id: str, instance_id: str) -> List[Dict[str, Any]]:
    """Get Identity Store users for an account and instance.

    Args:
        account_id: The AWS account ID.
        instance_id: The ID of the Identity Center instance.

    Returns:
        The list of Identity Store users, or an empty list if not found.
    """
    data = _load_data(f"identity_store_users_{instance_id}", account_id)
    if data is None:
        return []
    return data.get("users", [])


def save_identity_store_groups(account_id: str, instance_id: str, groups: List[Dict[str, Any]]) -> None:
    """Save Identity Store groups for an account and instance.

    Args:
        account_id: The AWS account ID.
        instance_id: The ID of the Identity Center instance.
        groups: The list of groups to save.
    """
    _save_data({"groups": groups}, f"identity_store_groups_{instance_id}", account_id)


def get_identity_store_groups(account_id: str, instance_id: str) -> List[Dict[str, Any]]:
    """Get Identity Store groups for an account and instance.

    Args:
        account_id: The AWS account ID.
        instance_id: The ID of the Identity Center instance.

    Returns:
        The list of Identity Store groups, or an empty list if not found.
    """
    data = _load_data(f"identity_store_groups_{instance_id}", account_id)
    if data is None:
        return []
    return data.get("groups", [])


def save_access_analyzers(account_id: str, analyzers: List[Dict[str, Any]]) -> None:
    """Save Access Analyzer analyzers for an account.

    Args:
        account_id: The AWS account ID.
        analyzers: The list of Access Analyzer analyzers to save.
    """
    _save_data({"analyzers": analyzers}, "access_analyzers", account_id)


def get_access_analyzers(account_id: str) -> List[Dict[str, Any]]:
    """Get Access Analyzer analyzers for an account.

    Args:
        account_id: The AWS account ID.

    Returns:
        The list of Access Analyzer analyzers, or an empty list if not found.
    """
    data = _load_data("access_analyzers", account_id)
    if data is None:
        return []
    return data.get("analyzers", [])


def save_iam_users(account_id: str, users: List[Dict[str, Any]]) -> None:
    """Save IAM users for an account.

    Args:
        account_id: The AWS account ID.
        users: The list of IAM users to save.
    """
    _save_data(users, "iam_users", account_id)


def get_iam_users(account_id: str) -> List[Dict[str, Any]]:
    """Get IAM users for an account.

    Args:
        account_id: The AWS account ID.
    """
    return _load_data("iam_users", account_id) or []


def save_iam_groups(account_id: str, groups: List[Dict[str, Any]]) -> None:
    """Save IAM groups for an account.

    Args:
        account_id: The AWS account ID.
        groups: The list of IAM groups to save.
    """
    _save_data(groups, "iam_groups", account_id)


def get_iam_groups(account_id: str) -> List[Dict[str, Any]]:
    """Get IAM groups for an account.

    Args:
        account_id: The AWS account ID.
    """
    return _load_data("iam_groups", account_id) or []


def save_config_recorders(account_id: str, region: str, recorders: List[Dict[str, Any]]) -> None:
    """Save Config recorders for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        recorders: The list of Config recorders to save.
    """
    _save_data(recorders, f"config_recorders_{region}", account_id)


def get_config_recorders(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Config recorders for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"config_recorders_{region}", account_id) or []


def save_config_delivery_channels(account_id: str, region: str, channels: List[Dict[str, Any]]) -> None:
    """Save Config delivery channels for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        channels: The list of Config delivery channels to save.
    """
    _save_data(channels, f"config_delivery_channels_{region}", account_id)


def get_config_delivery_channels(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Config delivery channels for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"config_delivery_channels_{region}", account_id) or []


def save_config_rules(account_id: str, region: str, rules: List[Dict[str, Any]]) -> None:
    """Save Config rules for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        rules: The list of Config rules to save.
    """
    _save_data(rules, f"config_rules_{region}", account_id)


def get_config_rules(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Config rules for an account.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"config_rules_{region}", account_id) or []


def save_cloudfront_origin_access_identities(account_id: str, identities: List[Dict[str, Any]]) -> None:
    """Save CloudFront origin access identities for an account.

    Args:
        account_id: The AWS account ID.
        identities: The list of CloudFront origin access identities to save.
    """
    _save_data(identities, "cloudfront_origin_access_identities", account_id)


def get_cloudfront_origin_access_identities(account_id: str) -> List[Dict[str, Any]]:
    """Get CloudFront origin access identities for an account.

    Args:
        account_id: The AWS account ID.
    """
    return _load_data("cloudfront_origin_access_identities", account_id) or []


def save_vpc_endpoints(account_id: str, region: str, endpoints: List[Dict[str, Any]]) -> None:
    """Save VPC endpoints for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        endpoints: The list of VPC endpoints to save.
    """
    _save_data(endpoints, f"vpc_endpoints_{region}", account_id)


def get_vpc_endpoints(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get VPC endpoints for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"vpc_endpoints_{region}", account_id) or []


def save_cloudtrail_trails(account_id: str, region: str, trails: List[Dict[str, Any]]) -> None:
    """Save CloudTrail trails for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        trails: The list of CloudTrail trails to save.
    """
    _save_data(trails, f"cloudtrail_trails_{region}", account_id)


def get_cloudtrail_trails(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get CloudTrail trails for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"cloudtrail_trails_{region}", account_id) or []


def save_flow_logs(account_id: str, region: str, logs: List[Dict[str, Any]]) -> None:
    """Save flow logs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        logs: The list of flow logs to save.
    """
    _save_data(logs, f"flow_logs_{region}", account_id)


def get_flow_logs(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get flow logs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"flow_logs_{region}", account_id) or []


def save_vpcs(account_id: str, region: str, vpcs: List[Dict[str, Any]]) -> None:
    """Save VPCs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        vpcs: The list of VPCs to save.
    """
    _save_data(vpcs, f"vpcs_{region}", account_id)


def get_vpcs(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get VPCs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"vpcs_{region}", account_id) or []


def save_route53resolver_query_log_configs(account_id: str, region: str, query_log_configs: List[Dict[str, Any]]) -> None:
    """Save Route 53 resolver query log configs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        query_log_configs: The list of Route 53 resolver query log configs to save.
    """
    _save_data(query_log_configs, f"route53resolver_query_log_configs_{region}", account_id)


def get_route53resolver_query_log_configs(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Route 53 resolver query log configs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"route53resolver_query_log_configs_{region}", account_id) or []


def save_route53resolver_query_log_config_associations(account_id: str, region: str, resolver_query_log_config_associations: List[Dict[str, Any]]) -> None:
    """Save Route 53 resolver query log config associations for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        resolver_query_log_config_associations: The list of Route 53 resolver query log config associations to save.
    """
    _save_data(resolver_query_log_config_associations, f"route53resolver_query_log_config_associations_{region}", account_id)


def get_route53resolver_query_log_config_associations(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Route 53 resolver query log config associations for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"route53resolver_query_log_config_associations_{region}", account_id) or []


def save_log_groups(account_id: str, region: str, log_groups: List[Dict[str, Any]]) -> None:
    """Save log groups for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        log_groups: The list of log groups to save.
    """
    _save_data(log_groups, f"log_groups_{region}", account_id)


def get_log_groups(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get log groups for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"log_groups_{region}", account_id) or []


def save_export_tasks(account_id: str, region: str, export_tasks: List[Dict[str, Any]]) -> None:
    """Save export tasks for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        export_tasks: The list of export tasks to save.
    """
    _save_data(export_tasks, f"export_tasks_{region}", account_id)


def get_export_tasks(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get export tasks for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"export_tasks_{region}", account_id) or []


def save_wafv2_web_acls(account_id: str, region: str, web_acls: List[Dict[str, Any]]) -> None:
    """Save WAFv2 web ACLs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        web_acls: The list of WAFv2 web ACLs to save.
    """
    _save_data(web_acls, f"wafv2_web_acls_{region}", account_id)


def get_wafv2_web_acls(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get WAFv2 web ACLs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"wafv2_web_acls_{region}", account_id) or []


def save_wafv2_logging_configurations(account_id: str, region: str, logging_configurations: List[Dict[str, Any]]) -> None:
    """Save WAFv2 logging configurations for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        logging_configurations: The list of WAFv2 logging configurations to save.
    """
    _save_data(logging_configurations, f"wafv2_logging_configurations_{region}", account_id)


def get_wafv2_logging_configurations(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get WAFv2 logging configurations for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"wafv2_logging_configurations_{region}", account_id) or []


def save_elbv2_load_balancers(account_id: str, region: str, load_balancers: List[Dict[str, Any]]) -> None:
    """Save ELBv2 load balancers for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        load_balancers: The list of ELBv2 load balancers to save.
    """
    _save_data(load_balancers, f"elbv2_load_balancers_{region}", account_id)


def get_elbv2_load_balancers(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get ELBv2 load balancers for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"elbv2_load_balancers_{region}", account_id) or []


def save_eks_clusters(account_id: str, region: str, clusters: List[Dict[str, Any]]) -> None:
    """Save EKS clusters for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        clusters: The list of EKS clusters to save.
    """
    _save_data(clusters, f"eks_clusters_{region}", account_id)


def get_eks_clusters(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get EKS clusters for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"eks_clusters_{region}", account_id) or []


def save_detective_graphs(account_id: str, region: str, graphs: List[Dict[str, Any]]) -> None:
    """Save Detective graphs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        graphs: The list of Detective graphs to save.
    """
    _save_data(graphs, f"detective_graphs_{region}", account_id)


def get_detective_graphs(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Detective graphs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"detective_graphs_{region}", account_id) or []


def save_securityhub_action_targets(account_id: str, region: str, action_targets: List[Dict[str, Any]]) -> None:
    """Save Security Hub action targets for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        action_targets: The list of Security Hub action targets to save.
    """
    _save_data(action_targets, f"securityhub_action_targets_{region}", account_id)


def get_securityhub_action_targets(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Security Hub action targets for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"securityhub_action_targets_{region}", account_id) or []


def save_securityhub_automation_rules(account_id: str, region: str, automation_rules: List[Dict[str, Any]]) -> None:
    """Save Security Hub automation rules for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        automation_rules: The list of Security Hub automation rules to save.
    """
    _save_data(automation_rules, f"securityhub_automation_rules_{region}", account_id)


def get_securityhub_automation_rules(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Security Hub automation rules for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"securityhub_automation_rules_{region}", account_id) or []


def save_dynamodb_tables(account_id: str, region: str, tables: List[Dict[str, Any]]) -> None:
    """Save DynamoDB tables for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        tables: The list of DynamoDB tables to save.
    """
    _save_data(tables, f"dynamodb_tables_{region}", account_id)


def get_dynamodb_tables(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get DynamoDB tables for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"dynamodb_tables_{region}", account_id) or []


def save_custom_key_stores(account_id: str, region: str, custom_key_stores: List[Dict[str, Any]]) -> None:
    """Save custom key stores for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        custom_key_stores: The list of custom key stores to save.
    """
    _save_data(custom_key_stores, f"custom_key_stores_{region}", account_id)


def get_custom_key_stores(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get custom key stores for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"custom_key_stores_{region}", account_id) or []


def save_config_compliance_by_rule(account_id: str, region: str, compliance: List[Dict[str, Any]]) -> None:
    """Save Config compliance by rule for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        compliance: The list of Config compliance by rule to save.
    """
    _save_data(compliance, f"config_compliance_by_rule_{region}", account_id)


def get_config_compliance_by_rule(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Config compliance by rule for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"config_compliance_by_rule_{region}", account_id) or []


def save_guardduty_detectors(account_id: str, region: str, detectors: List[Dict[str, Any]]) -> None:
    """Save GuardDuty detectors for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        detectors: The list of GuardDuty detectors to save.
    """
    _save_data(detectors, f"guardduty_detectors_{region}", account_id)


def get_guardduty_detectors(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get GuardDuty detectors for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"guardduty_detectors_{region}", account_id) or []


def save_backup_vaults(account_id: str, region: str, vaults: List[Dict[str, Any]]) -> None:
    """Save Backup vaults for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        vaults: The list of Backup vaults to save.
    """
    _save_data(vaults, f"backup_vaults_{region}", account_id)


def get_backup_vaults(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Backup vaults for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"backup_vaults_{region}", account_id) or []


def save_backup_protected_resources(account_id: str, region: str, resources: List[Dict[str, Any]]) -> None:
    """Save Backup protected resources for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        resources: The list of Backup protected resources to save.
    """
    _save_data(resources, f"backup_protected_resources_{region}", account_id)


def get_backup_protected_resources(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Backup protected resources for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"backup_protected_resources_{region}", account_id) or []


def save_acm_certificates(account_id: str, region: str, certificates: List[Dict[str, Any]]) -> None:
    """Save ACM certificates for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        certificates: The list of ACM certificates to save.
    """
    _save_data(certificates, f"acm_certificates_{region}", account_id)


def get_acm_certificates(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get ACM certificates for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"acm_certificates_{region}", account_id) or []


def save_acm_pca_certificate_authorities(account_id: str, region: str, authorities: List[Dict[str, Any]]) -> None:
    """Save ACM PCA certificate authorities for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        authorities: The list of ACM PCA certificate authorities to save.
    """
    _save_data(authorities, f"acm_pca_certificate_authorities_{region}", account_id)


def get_acm_pca_certificate_authorities(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get ACM PCA certificate authorities for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"acm_pca_certificate_authorities_{region}", account_id) or []


def save_inspector2_configuration(account_id: str, region: str, configuration: Dict[str, Any]) -> None:
    """Save Inspector2 configuration for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        configuration: The Inspector2 configuration to save.
    """
    _save_data(configuration, f"inspector2_configuration_{region}", account_id)


def get_inspector2_configuration(account_id: str, region: str) -> Dict[str, Any]:
    """Get Inspector2 configuration for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"inspector2_configuration_{region}", account_id) or {}


def save_inspector2_coverage(account_id: str, region: str, coverage: List[Dict[str, Any]]) -> None:
    """Save Inspector2 coverage for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        coverage: The Inspector2 coverage to save.
    """
    _save_data(coverage, f"inspector2_coverage_{region}", account_id)


def get_inspector2_coverage(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get Inspector2 coverage for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"inspector2_coverage_{region}", account_id) or []


def save_maintenance_windows(account_id: str, region: str, maintenance_windows: List[Dict[str, Any]]) -> None:
    """Save maintenance windows for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        maintenance_windows: The list of maintenance windows to save.
    """
    _save_data(maintenance_windows, f"maintenance_windows_{region}", account_id)


def get_maintenance_windows(account_id: str, region: str) -> List[Dict[str, Any]]:
    """Get maintenance windows for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"maintenance_windows_{region}", account_id) or []
