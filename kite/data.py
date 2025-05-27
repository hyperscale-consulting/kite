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


def save_bucket_policies(account_id: str, buckets: List[Dict[str, Any]]) -> None:
    """
    Save S3 bucket policies for an account.

    Args:
        account_id: The AWS account ID to save the policies for.
        buckets: The list of S3 buckets with their policies.
    """
    _save_data(buckets, "s3_bucket_policies", account_id)


def get_bucket_policies(account_id: str) -> List[Dict[str, Any]]:
    """
    Get S3 bucket policies for an account.

    Args:
        account_id: The AWS account ID to get the policies for.

    Returns:
        List of dictionaries containing bucket information and policies.
    """
    return _load_data("s3_bucket_policies", account_id) or []


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


def save_config_rules(account_id: str, rules: List[Dict[str, Any]]) -> None:
    """Save Config rules for an account.

    Args:
        account_id: The AWS account ID.
        rules: The list of Config rules to save.
    """
    _save_data(rules, "config_rules", account_id)


def get_config_rules(account_id: str) -> List[Dict[str, Any]]:
    """Get Config rules for an account.

    Args:
        account_id: The AWS account ID.
    """
    return _load_data("config_rules", account_id) or []


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
