import json
import os
from dataclasses import asdict
from datetime import datetime
from typing import Any

import click

from hyperscale.kite.config import Config
from hyperscale.kite.models import DelegatedAdmin
from hyperscale.kite.models import Organization


def _save_data(data: Any, data_type: str, account_id: str | None = None) -> None:
    """Save data to a file in the data directory.

    Args:
        data: The data to save.
        data_type: The type of data being saved.
        account_id: The AWS account ID to save the data for.
    """
    config = Config.get()
    # Create data directory if it doesn't exist
    os.makedirs(config.data_dir, exist_ok=True)

    sub_dir = account_id if account_id else "global"
    # Create account-specific directory if needed
    account_dir = f"{config.data_dir}/{sub_dir}"
    os.makedirs(account_dir, exist_ok=True)

    # Save data to file
    file_path = f"{account_dir}/{data_type}.json"
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def _load_data(data_type: str, account_id: str | None = None) -> Any:
    """Load data from a file in the data directory.

    Args:
        data_type: The type of data to load.
        account_id: The AWS account ID to load the data for.

    Returns:
        The loaded data, or an empty list if the file doesn't exist.
    """
    config = Config.get()
    if not account_id:
        account_id = "global"
    file_path = f"{config.data_dir}/{account_id}/{data_type}.json"
    try:
        with open(file_path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def get_organization() -> Organization | None:
    """Get the organization data.

    Returns:
        The organization data, or None if not found.
    """
    config = Config.get()
    if not config.management_account_id:
        return None
    data = _load_data("organization", config.management_account_id)
    if data is None:
        return None
    return Organization.from_dict(data)


def save_organization(account_id: str, org: Organization) -> None:
    """Save the organization data."""
    _save_data(asdict(org), "organization", account_id)


def get_delegated_admins() -> list[DelegatedAdmin]:
    """Get the delegated administrators data.

    Returns:
        The delegated administrators data, or None if not found.
    """
    config = Config.get()
    if not config.management_account_id:
        return []
    data = _load_data("delegated_admins", config.management_account_id) or []

    # Convert the JSON data back into DelegatedAdmin objects
    return [DelegatedAdmin.from_dict(admin) for admin in data]


def save_delegated_admins(account_id: str, admins: list[DelegatedAdmin]) -> None:
    """Save delegated administrators data.

    Args:
        admins: The delegated administrators data to save.
    """
    _save_data([asdict(admin) for admin in admins], "delegated_admins", account_id)


def save_organization_features(account_id: str, features: list[str]) -> None:
    """Save organization features.

    Args:
        features: The list of organization features to save.
        account_id: The AWS account ID to save the features for.
    """
    _save_data(features, "organization_features", account_id)


def get_organization_features() -> list[str]:
    """Get organization features.

    Returns:
        The list of organization features, or None if not found.
    """
    config = Config.get()
    if not config.management_account_id:
        return []
    return _load_data("organization_features", config.management_account_id) or []


def save_credentials_report(account_id: str, report: dict[str, Any]) -> None:
    """Save credentials report for an account.

    Args:
        account_id: The AWS account ID to save the report for.
        report: The credentials report data to save.
    """
    _save_data(report, "credentials_report", account_id)


def get_credentials_report(account_id: str) -> dict[str, Any]:
    """Get credentials report for an account.

    Args:
        account_id: The AWS account ID to get the report for.

    Returns:
        The credentials report data, or None if not found.
    """
    return _load_data("credentials_report", account_id)


def save_account_summary(account_id: str, summary: dict[str, Any]) -> None:
    """Save account summary for an account.

    Args:
        account_id: The AWS account ID to save the summary for.
        summary: The account summary data to save.
    """
    _save_data(summary, "account_summary", account_id)


def get_account_summary(account_id: str) -> dict[str, Any] | None:
    """Get account summary for an account.

    Args:
        account_id: The AWS account ID to get the summary for.

    Returns:
        The account summary data, or None if not found.
    """
    return _load_data("account_summary", account_id)


def save_saml_providers(
    account_id: str,
    providers: list[dict[str, Any]],
) -> None:
    """Save SAML providers.

    Args:
        account_id: The AWS account ID to save the providers for.
        providers: The list of SAML providers to save.
    """
    _save_data(providers, "saml_providers", account_id)


def get_saml_providers(
    account_id: str,
) -> list[dict[str, Any]]:
    """Get SAML providers.

    Returns:
        The list of SAML providers, or None if not found.
    """
    return _load_data("saml_providers", account_id) or []


def save_oidc_providers(account_id: str, providers: list[dict[str, Any]]) -> None:
    """Save OIDC providers.

    Args:
        account_id: The AWS account ID to save the providers for.
        providers: The list of OIDC providers to save.
    """
    _save_data(providers, "oidc_providers", account_id)


def get_oidc_providers(
    account_id: str,
) -> list[dict[str, Any]]:
    """Get OIDC providers.

    Returns:
        The list of OIDC providers, or None if not found.
    """
    return _load_data("oidc_providers", account_id) or []


def save_identity_center_instances(
    account_id: str, instances: list[dict[str, Any]]
) -> None:
    """Save Identity Center instances.

    Args:
        instances: The list of Identity Center instances to save.
        account_id: The AWS account ID to save the instances for.
    """
    _save_data(instances, "identity_center_instances", account_id)


def get_identity_center_instances() -> list[dict[str, Any]]:
    """Get Identity Center instances.

    Returns:
        The list of Identity Center instances, or None if not found.
    """
    mgmt_account_id = Config.get().management_account_id
    if not mgmt_account_id:
        # we're only interested in organizational instances
        return []
    return _load_data("identity_center_instances", mgmt_account_id) or []


def save_ec2_instances(
    account_id: str, region: str, instances: list[dict[str, Any]]
) -> None:
    """Save EC2 instances for an account.

    Args:
        account_id: The AWS account ID to save the instances for.
        region: The AWS region to save the instances for.
        instances: The list of EC2 instances to save.
    """
    _save_data(instances, f"ec2_instances_{region}", account_id)


def get_ec2_instances(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get EC2 instances for an account.

    Args:
        account_id: The AWS account ID to get the instances for.
        region: The AWS region to get the instances for.
    Returns:
        The list of EC2 instances, or None if not found.
    """
    return _load_data(f"ec2_instances_{region}", account_id) or []


def save_collection_metadata() -> None:
    """Save metadata about the last data collection run."""
    metadata = {
        "timestamp": datetime.now().isoformat(),
        "external_id": Config.get().external_id,
    }
    _save_data(metadata, "collection_metadata")


def get_collection_metadata() -> dict[str, Any] | None:
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


def save_virtual_mfa_devices(account_id: str, devices: list[dict[str, Any]]) -> None:
    """
    Save virtual MFA devices for an account.

    Args:
        account_id: The AWS account ID.
        devices: List of virtual MFA device information.
    """
    _save_data(devices, "virtual_mfa_devices", account_id)


def get_virtual_mfa_devices(account_id: str) -> list[dict[str, Any]]:
    """
    Get virtual MFA devices for an account.

    Args:
        account_id: The AWS account ID.

    Returns:
        List of virtual MFA device information.
    """
    return _load_data("virtual_mfa_devices", account_id)


def save_password_policy(account_id: str, policy: dict[str, Any]) -> None:
    """
    Save password policy for an account.

    Args:
        account_id: The AWS account ID to save the policy for.
        policy: The password policy data to save.
    """
    _save_data(policy, "password_policy", account_id)


def get_password_policy(account_id: str) -> dict[str, Any] | None:
    """
    Get password policy for an account.

    Args:
        account_id: The AWS account ID to get the policy for.

    Returns:
        The password policy data, or None if not found.
    """
    return _load_data("password_policy", account_id)


def save_cognito_user_pools(
    account_id: str, region: str, pools: list[dict[str, Any]]
) -> None:
    """
    Save Cognito user pools for an account.

    Args:
        account_id: The AWS account ID to save the pools for.
        region: The AWS region to save the pools for.
        pools: The list of Cognito user pools to save.
    """
    _save_data(pools, f"cognito_user_pools_{region}", account_id)


def get_cognito_user_pools(account_id: str, region: str) -> list[dict[str, Any]]:
    """
    Get Cognito user pools for an account.

    Args:
        account_id: The AWS account ID to get the pools for.
        region: The AWS region to get the pools for.
    Returns:
        List of dictionaries containing user pool information, or empty list.
    """
    return _load_data(f"cognito_user_pools_{region}", account_id) or []


def get_cognito_user_pool(
    account_id: str, region: str, user_pool_id: str
) -> dict[str, Any]:
    """
    Get details for a specific Cognito user pool.

    Args:
        account_id: The AWS account ID.
        region: The AWS region to get the pool for.
        user_pool_id: The ID of the Cognito user pool.

    Returns:
        Dictionary containing the user pool information, or empty dict if not found.
    """
    for pool in get_cognito_user_pools(account_id, region):
        if pool["Id"] == user_pool_id:
            return pool
    return {}


def save_key_pairs(account_id: str, key_pairs: list[dict[str, Any]]) -> None:
    """
    Save EC2 key pairs for an account.

    Args:
        account_id: The AWS account ID to save the key pairs for.
        key_pairs: The list of EC2 key pairs to save.
    """
    _save_data(key_pairs, "ec2_key_pairs", account_id)


def get_key_pairs(account_id: str) -> list[dict[str, Any]]:
    """
    Get EC2 key pairs for an account.

    Args:
        account_id: The AWS account ID to get the key pairs for.

    Returns:
        List of dictionaries containing key pair information, or empty list.
    """
    return _load_data("ec2_key_pairs", account_id) or []


def save_secrets(account_id: str, region: str, secrets: list[dict[str, Any]]) -> None:
    """
    Save Secrets Manager secrets for an account and region.

    Args:
        account_id: The AWS account ID to save the secrets for.
        region: The AWS region to save the secrets for.
        secrets: The list of secrets to save.
    """
    _save_data(secrets, f"secrets_{region}", account_id)


def get_secrets(account_id: str, region: str) -> list[dict[str, Any]]:
    """
    Get Secrets Manager secrets for an account and region.

    Args:
        account_id: The AWS account ID to get the secrets for.
        region: The AWS region to get the secrets for.

    Returns:
        List of dictionaries containing secret information, or empty list.
    """
    return _load_data(f"secrets_{region}", account_id) or []


def save_roles(account_id: str, roles: list[dict[str, Any]]) -> None:
    """
    Save IAM roles for an account.

    Args:
        account_id: The AWS account ID to save the roles for.
        roles: The list of IAM roles to save.
    """
    _save_data(roles, "iam_roles", account_id)


def get_roles(account_id: str) -> list[dict[str, Any]]:
    """
    Get IAM roles for an account.

    Args:
        account_id: The AWS account ID to get the roles for.

    Returns:
        List of dictionaries containing role information, or empty list.
    """
    return _load_data("iam_roles", account_id) or []


def get_role_by_arn(role_arn: str) -> dict[str, Any] | None:
    """
    Get a specific IAM role by arn.

    Args:
        role_arn: The arn of the IAM role.

    Returns:
        Dictionary containing the role information, or None if not found.
    """
    account_id = role_arn.split(":")[4]  # Extract account ID from ARN
    roles = get_roles(account_id)
    for role in roles:
        if role["RoleArn"] == role_arn:
            return role
    return None


def save_customer_managed_policies(
    account_id: str, policies: list[dict[str, Any]]
) -> None:
    """
    Save customer managed policies for an account.

    Args:
        account_id: The AWS account ID to save the policies for.
        policies: The list of customer managed policies to save.
    """
    _save_data(policies, "customer_managed_policies", account_id)


def get_customer_managed_policies(account_id: str) -> list[dict[str, Any]]:
    """
    Get customer managed policies for an account.

    Args:
        account_id: The AWS account ID to get the policies for.

    Returns:
        List of dictionaries containing policy information, or empty list.
    """
    return _load_data("customer_managed_policies", account_id) or []


def save_bucket_metadata(account_id: str, buckets: list[dict[str, Any]]) -> None:
    """
    Save S3 bucket metadata for an account.

    Args:
        account_id: The AWS account ID to save the metadata for.
        buckets: The list of S3 buckets with their policies.
    """
    _save_data(buckets, "bucket_metadata", account_id)


def get_bucket_metadata(account_id: str) -> list[dict[str, Any]]:
    """
    Get S3 bucket metadata for an account.

    Args:
        account_id: The AWS account ID to get the metadata for.

    Returns:
        List of dictionaries containing bucket information and policies.
    """
    return _load_data("bucket_metadata", account_id) or []


def save_sns_topics(account_id: str, region: str, topics: list[dict[str, Any]]) -> None:
    """Save SNS topics for an account and region.

    Args:
        account_id: The AWS account ID to save the topics for.
        region: The AWS region to save the topics for.
        topics: The list of SNS topics to save.
    """
    _save_data(topics, f"sns_topics_{region}", account_id)


def get_sns_topics(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get SNS topics for an account and region.

    Args:
        account_id: The AWS account ID to get the topics for.
        region: The AWS region to get the topics for.

    Returns:
        The list of SNS topics, or an empty list if not found.
    """
    return _load_data(f"sns_topics_{region}", account_id) or []


def save_sqs_queues(account_id: str, region: str, queues: list[dict[str, Any]]) -> None:
    """Save SQS queues for an account and region.

    Args:
        account_id: The AWS account ID to save the queues for.
        region: The AWS region to save the queues for.
        queues: The list of SQS queues to save.
    """
    _save_data(queues, f"sqs_queues_{region}", account_id)


def get_sqs_queues(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get SQS queues for an account and region.

    Args:
        account_id: The AWS account ID to get the queues for.
        region: The AWS region to get the queues for.

    Returns:
        The list of SQS queues, or an empty list if not found.
    """
    return _load_data(f"sqs_queues_{region}", account_id) or []


def save_lambda_functions(
    account_id: str, region: str, functions: list[dict[str, Any]]
) -> None:
    """Save Lambda functions for an account and region.

    Args:
        account_id: The AWS account ID to save the functions for.
        region: The AWS region to save the functions for.
        functions: The list of Lambda functions to save.
    """
    _save_data(functions, f"lambda_functions_{region}", account_id)


def get_lambda_functions(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get Lambda functions for an account and region.

    Args:
        account_id: The AWS account ID to get the functions for.
        region: The AWS region to get the functions for.

    Returns:
        The list of Lambda functions, or an empty list if not found.
    """
    return _load_data(f"lambda_functions_{region}", account_id) or []


def save_kms_keys(account_id: str, region: str, keys: list[dict[str, Any]]) -> None:
    """Save KMS keys for an account and region.

    Args:
        account_id: The AWS account ID to save the keys for.
        region: The AWS region to save the keys for.
        keys: The list of KMS keys to save.
    """
    _save_data(keys, f"kms_keys_{region}", account_id)


def get_kms_keys(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get KMS keys for an account and region.

    Args:
        account_id: The AWS account ID to get the keys for.
        region: The AWS region to get the keys for.

    Returns:
        The list of KMS keys, or an empty list if not found.
    """
    return _load_data(f"kms_keys_{region}", account_id) or []


def save_identity_center_permission_sets(
    account_id: str, instance_id: str, permission_sets: list[dict[str, Any]]
) -> None:
    """Save Identity Center permission sets for an account and instance.

    Args:
        account_id: The AWS account ID.
        instance_id: The ID of the Identity Center instance.
        permission_sets: The list of permission sets to save.
    """
    _save_data(
        permission_sets, f"identity_center_permission_sets_{instance_id}", account_id
    )


def get_identity_center_permission_sets(
    account_id: str, instance_id: str
) -> list[dict[str, Any]]:
    """Get Identity Center permission sets for an account and instance.

    Args:
        account_id: The AWS account ID.
        instance_id: The ID of the Identity Center instance.

    Returns:
        The list of Identity Center permission sets, or an empty list if not found.
    """
    return (
        _load_data(f"identity_center_permission_sets_{instance_id}", account_id) or []
    )


def save_access_analyzers(account_id: str, analyzers: list[dict[str, Any]]) -> None:
    """Save Access Analyzer analyzers for an account.

    Args:
        account_id: The AWS account ID.
        analyzers: The list of Access Analyzer analyzers to save.
    """
    _save_data(analyzers, "access_analyzers", account_id)


def get_access_analyzers(account_id: str) -> list[dict[str, Any]]:
    """Get Access Analyzer analyzers for an account.

    Args:
        account_id: The AWS account ID.

    Returns:
        The list of Access Analyzer analyzers, or an empty list if not found.
    """
    return _load_data("access_analyzers", account_id) or []


def save_iam_users(account_id: str, users: list[dict[str, Any]]) -> None:
    """Save IAM users for an account.

    Args:
        account_id: The AWS account ID.
        users: The list of IAM users to save.
    """
    _save_data(users, "iam_users", account_id)


def get_iam_users(account_id: str) -> list[dict[str, Any]]:
    """Get IAM users for an account.

    Args:
        account_id: The AWS account ID.
    """
    return _load_data("iam_users", account_id) or []


def save_iam_groups(account_id: str, groups: list[dict[str, Any]]) -> None:
    """Save IAM groups for an account.

    Args:
        account_id: The AWS account ID.
        groups: The list of IAM groups to save.
    """
    _save_data(groups, "iam_groups", account_id)


def get_iam_groups(account_id: str) -> list[dict[str, Any]]:
    """Get IAM groups for an account.

    Args:
        account_id: The AWS account ID.
    """
    return _load_data("iam_groups", account_id) or []


def save_config_recorders(
    account_id: str, region: str, recorders: list[dict[str, Any]]
) -> None:
    """Save Config recorders for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        recorders: The list of Config recorders to save.
    """
    _save_data(recorders, f"config_recorders_{region}", account_id)


def get_config_recorders(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get Config recorders for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"config_recorders_{region}", account_id) or []


def save_config_delivery_channels(
    account_id: str, region: str, channels: list[dict[str, Any]]
) -> None:
    """Save Config delivery channels for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        channels: The list of Config delivery channels to save.
    """
    _save_data(channels, f"config_delivery_channels_{region}", account_id)


def get_config_delivery_channels(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get Config delivery channels for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"config_delivery_channels_{region}", account_id) or []


def save_config_rules(
    account_id: str, region: str, rules: list[dict[str, Any]]
) -> None:
    """Save Config rules for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        rules: The list of Config rules to save.
    """
    _save_data(rules, f"config_rules_{region}", account_id)


def get_config_rules(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get Config rules for an account.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"config_rules_{region}", account_id) or []


def save_cloudfront_origin_access_identities(
    account_id: str, identities: list[dict[str, Any]]
) -> None:
    """Save CloudFront origin access identities for an account.

    Args:
        account_id: The AWS account ID.
        identities: The list of CloudFront origin access identities to save.
    """
    _save_data(identities, "cloudfront_origin_access_identities", account_id)


def get_cloudfront_origin_access_identities(account_id: str) -> list[dict[str, Any]]:
    """Get CloudFront origin access identities for an account.

    Args:
        account_id: The AWS account ID.
    """
    return _load_data("cloudfront_origin_access_identities", account_id) or []


def save_vpc_endpoints(
    account_id: str, region: str, endpoints: list[dict[str, Any]]
) -> None:
    """Save VPC endpoints for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        endpoints: The list of VPC endpoints to save.
    """
    _save_data(endpoints, f"vpc_endpoints_{region}", account_id)


def get_vpc_endpoints(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get VPC endpoints for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"vpc_endpoints_{region}", account_id) or []


def save_cloudtrail_trails(
    account_id: str, region: str, trails: list[dict[str, Any]]
) -> None:
    """Save CloudTrail trails for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        trails: The list of CloudTrail trails to save.
    """
    _save_data(trails, f"cloudtrail_trails_{region}", account_id)


def get_cloudtrail_trails(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get CloudTrail trails for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"cloudtrail_trails_{region}", account_id) or []


def save_flow_logs(account_id: str, region: str, logs: list[dict[str, Any]]) -> None:
    """Save flow logs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        logs: The list of flow logs to save.
    """
    _save_data(logs, f"flow_logs_{region}", account_id)


def get_flow_logs(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get flow logs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"flow_logs_{region}", account_id) or []


def save_vpcs(account_id: str, region: str, vpcs: list[dict[str, Any]]) -> None:
    """Save VPCs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        vpcs: The list of VPCs to save.
    """
    _save_data(vpcs, f"vpcs_{region}", account_id)


def get_vpcs(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get VPCs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"vpcs_{region}", account_id) or []


def save_route53resolver_query_log_configs(
    account_id: str, region: str, query_log_configs: list[dict[str, Any]]
) -> None:
    """Save Route 53 resolver query log configs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        query_log_configs: The list of Route 53 resolver query log configs to save.
    """
    _save_data(
        query_log_configs, f"route53resolver_query_log_configs_{region}", account_id
    )


def get_route53resolver_query_log_configs(
    account_id: str, region: str
) -> list[dict[str, Any]]:
    """Get Route 53 resolver query log configs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"route53resolver_query_log_configs_{region}", account_id) or []


def save_route53resolver_query_log_config_associations(
    account_id: str,
    region: str,
    resolver_query_log_config_associations: list[dict[str, Any]],
) -> None:
    """Save Route 53 resolver query log config associations for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        resolver_query_log_config_associations: The list of Route 53 resolver query
        log config associations to save.
    """
    _save_data(
        resolver_query_log_config_associations,
        f"route53resolver_query_log_config_associations_{region}",
        account_id,
    )


def get_route53resolver_query_log_config_associations(
    account_id: str, region: str
) -> list[dict[str, Any]]:
    """Get Route 53 resolver query log config associations for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return (
        _load_data(
            f"route53resolver_query_log_config_associations_{region}", account_id
        )
        or []
    )


def save_log_groups(
    account_id: str, region: str, log_groups: list[dict[str, Any]]
) -> None:
    """Save log groups for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        log_groups: The list of log groups to save.
    """
    _save_data(log_groups, f"log_groups_{region}", account_id)


def get_log_groups(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get log groups for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"log_groups_{region}", account_id) or []


def save_export_tasks(
    account_id: str, region: str, export_tasks: list[dict[str, Any]]
) -> None:
    """Save export tasks for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        export_tasks: The list of export tasks to save.
    """
    _save_data(export_tasks, f"export_tasks_{region}", account_id)


def get_export_tasks(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get export tasks for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"export_tasks_{region}", account_id) or []


def save_elbv2_load_balancers(
    account_id: str, region: str, load_balancers: list[dict[str, Any]]
) -> None:
    """Save ELBv2 load balancers for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        load_balancers: The list of ELBv2 load balancers to save.
    """
    _save_data(load_balancers, f"elbv2_load_balancers_{region}", account_id)


def get_elbv2_load_balancers(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get ELBv2 load balancers for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"elbv2_load_balancers_{region}", account_id) or []


def save_eks_clusters(
    account_id: str, region: str, clusters: list[dict[str, Any]]
) -> None:
    """Save EKS clusters for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        clusters: The list of EKS clusters to save.
    """
    _save_data(clusters, f"eks_clusters_{region}", account_id)


def get_eks_clusters(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get EKS clusters for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"eks_clusters_{region}", account_id) or []


def save_detective_graphs(
    account_id: str, region: str, graphs: list[dict[str, Any]]
) -> None:
    """Save Detective graphs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        graphs: The list of Detective graphs to save.
    """
    _save_data(graphs, f"detective_graphs_{region}", account_id)


def get_detective_graphs(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get Detective graphs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"detective_graphs_{region}", account_id) or []


def save_securityhub_action_targets(
    account_id: str, region: str, action_targets: list[dict[str, Any]]
) -> None:
    """Save Security Hub action targets for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        action_targets: The list of Security Hub action targets to save.
    """
    _save_data(action_targets, f"securityhub_action_targets_{region}", account_id)


def get_securityhub_action_targets(
    account_id: str, region: str
) -> list[dict[str, Any]]:
    """Get Security Hub action targets for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"securityhub_action_targets_{region}", account_id) or []


def save_securityhub_automation_rules(
    account_id: str, region: str, automation_rules: list[dict[str, Any]]
) -> None:
    """Save Security Hub automation rules for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        automation_rules: The list of Security Hub automation rules to save.
    """
    _save_data(automation_rules, f"securityhub_automation_rules_{region}", account_id)


def get_securityhub_automation_rules(
    account_id: str, region: str
) -> list[dict[str, Any]]:
    """Get Security Hub automation rules for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"securityhub_automation_rules_{region}", account_id) or []


def save_dynamodb_tables(
    account_id: str, region: str, tables: list[dict[str, Any]]
) -> None:
    """Save DynamoDB tables for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        tables: The list of DynamoDB tables to save.
    """
    _save_data(tables, f"dynamodb_tables_{region}", account_id)


def get_dynamodb_tables(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get DynamoDB tables for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"dynamodb_tables_{region}", account_id) or []


def save_custom_key_stores(
    account_id: str, region: str, custom_key_stores: list[dict[str, Any]]
) -> None:
    """Save custom key stores for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        custom_key_stores: The list of custom key stores to save.
    """
    _save_data(custom_key_stores, f"custom_key_stores_{region}", account_id)


def get_custom_key_stores(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get custom key stores for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"custom_key_stores_{region}", account_id) or []


def save_config_compliance_by_rule(
    account_id: str, region: str, compliance: list[dict[str, Any]]
) -> None:
    """Save Config compliance by rule for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        compliance: The list of Config compliance by rule to save.
    """
    _save_data(compliance, f"config_compliance_by_rule_{region}", account_id)


def get_config_compliance_by_rule(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get Config compliance by rule for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"config_compliance_by_rule_{region}", account_id) or []


def save_guardduty_detectors(
    account_id: str, region: str, detectors: list[dict[str, Any]]
) -> None:
    """Save GuardDuty detectors for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        detectors: The list of GuardDuty detectors to save.
    """
    _save_data(detectors, f"guardduty_detectors_{region}", account_id)


def get_guardduty_detectors(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get GuardDuty detectors for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"guardduty_detectors_{region}", account_id) or []


def save_backup_vaults(
    account_id: str, region: str, vaults: list[dict[str, Any]]
) -> None:
    """Save Backup vaults for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        vaults: The list of Backup vaults to save.
    """
    _save_data(vaults, f"backup_vaults_{region}", account_id)


def get_backup_vaults(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get Backup vaults for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"backup_vaults_{region}", account_id) or []


def save_backup_protected_resources(
    account_id: str, region: str, resources: list[dict[str, Any]]
) -> None:
    """Save Backup protected resources for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        resources: The list of Backup protected resources to save.
    """
    _save_data(resources, f"backup_protected_resources_{region}", account_id)


def get_backup_protected_resources(
    account_id: str, region: str
) -> list[dict[str, Any]]:
    """Get Backup protected resources for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"backup_protected_resources_{region}", account_id) or []


def save_acm_certificates(
    account_id: str, region: str, certificates: list[dict[str, Any]]
) -> None:
    """Save ACM certificates for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        certificates: The list of ACM certificates to save.
    """
    _save_data(certificates, f"acm_certificates_{region}", account_id)


def get_acm_certificates(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get ACM certificates for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"acm_certificates_{region}", account_id) or []


def save_acm_pca_certificate_authorities(
    account_id: str, region: str, authorities: list[dict[str, Any]]
) -> None:
    """Save ACM PCA certificate authorities for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        authorities: The list of ACM PCA certificate authorities to save.
    """
    _save_data(authorities, f"acm_pca_certificate_authorities_{region}", account_id)


def get_acm_pca_certificate_authorities(
    account_id: str, region: str
) -> list[dict[str, Any]]:
    """Get ACM PCA certificate authorities for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"acm_pca_certificate_authorities_{region}", account_id) or []


def save_inspector2_configuration(
    account_id: str, region: str, configuration: dict[str, Any]
) -> None:
    """Save Inspector2 configuration for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        configuration: The Inspector2 configuration to save.
    """
    _save_data(configuration, f"inspector2_configuration_{region}", account_id)


def get_inspector2_configuration(account_id: str, region: str) -> dict[str, Any]:
    """Get Inspector2 configuration for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"inspector2_configuration_{region}", account_id) or {}


def save_inspector2_coverage(
    account_id: str, region: str, coverage: list[dict[str, Any]]
) -> None:
    """Save Inspector2 coverage for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        coverage: The Inspector2 coverage to save.
    """
    _save_data(coverage, f"inspector2_coverage_{region}", account_id)


def get_inspector2_coverage(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get Inspector2 coverage for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"inspector2_coverage_{region}", account_id) or []


def save_maintenance_windows(
    account_id: str, region: str, maintenance_windows: list[dict[str, Any]]
) -> None:
    """Save maintenance windows for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        maintenance_windows: The list of maintenance windows to save.
    """
    _save_data(maintenance_windows, f"maintenance_windows_{region}", account_id)


def get_maintenance_windows(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get maintenance windows for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"maintenance_windows_{region}", account_id) or []


def save_ecs_clusters(
    account_id: str, region: str, clusters: list[dict[str, Any]]
) -> None:
    """Save ECS clusters for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        clusters: The list of ECS clusters to save.
    """
    _save_data(clusters, f"ecs_clusters_{region}", account_id)


def get_ecs_clusters(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get ECS clusters for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"ecs_clusters_{region}", account_id) or []


def save_rds_instances(
    account_id: str, region: str, instances: list[dict[str, Any]]
) -> None:
    """Save RDS instances for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        instances: The list of RDS instances to save.
    """
    _save_data(instances, f"rds_instances_{region}", account_id)


def get_rds_instances(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get RDS instances for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"rds_instances_{region}", account_id) or []


def save_subnets(account_id: str, region: str, subnets: list[dict[str, Any]]) -> None:
    """Save subnets for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        subnets: The list of subnets to save.
    """
    _save_data(subnets, f"subnets_{region}", account_id)


def get_subnets(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get subnets for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"subnets_{region}", account_id) or []


def save_efs_file_systems(
    account_id: str, region: str, file_systems: list[dict[str, Any]]
) -> None:
    """Save EFS file systems for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        file_systems: The list of EFS file systems to save.
    """
    _save_data(file_systems, f"efs_file_systems_{region}", account_id)


def get_efs_file_systems(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get EFS file systems for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"efs_file_systems_{region}", account_id) or []


def save_rtbs(account_id: str, region: str, rtbs: list[dict[str, Any]]) -> None:
    """Save route tables for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        rtbs: The list of route tables to save.
    """
    _save_data(rtbs, f"rtbs_{region}", account_id)


def get_rtbs(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get route tables for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"rtbs_{region}", account_id) or []


def save_nacls(account_id: str, region: str, nacls: list[dict[str, Any]]) -> None:
    """Save network ACLs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        nacls: The list of network ACLs to save.
    """
    _save_data(nacls, f"nacls_{region}", account_id)


def get_nacls(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get network ACLs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"nacls_{region}", account_id) or []


def save_security_groups(
    account_id: str, region: str, security_groups: list[dict[str, Any]]
) -> None:
    """Save security groups for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        security_groups: The list of security groups to save.
    """
    _save_data(security_groups, f"security_groups_{region}", account_id)


def get_security_groups(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get security groups for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"security_groups_{region}", account_id) or []


def save_vpc_peering_connections(
    account_id: str, region: str, vpc_peering_connections: list[dict[str, Any]]
) -> None:
    """Save VPC peering connections for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        vpc_peering_connections: The list of VPC peering connections to save.
    """
    _save_data(vpc_peering_connections, f"vpc_peering_connections_{region}", account_id)


def get_vpc_peering_connections(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get VPC peering connections for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"vpc_peering_connections_{region}", account_id) or []


def save_route53resolver_firewall_rule_groups(
    account_id: str, region: str, firewall_rule_groups: list[dict[str, Any]]
) -> None:
    """Save Route 53 Resolver firewall rule groups for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        firewall_rule_groups: The list of Route 53 Resolver firewall rule groups to
        save.
    """
    _save_data(
        firewall_rule_groups,
        f"route53resolver_firewall_rule_groups_{region}",
        account_id,
    )


def get_route53resolver_firewall_rule_groups(
    account_id: str, region: str
) -> list[dict[str, Any]]:
    """Get Route 53 Resolver firewall rule groups for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return (
        _load_data(f"route53resolver_firewall_rule_groups_{region}", account_id) or []
    )


def save_route53resolver_firewall_rule_group_associations(
    account_id: str, region: str, firewall_rule_group_associations: list[dict[str, Any]]
) -> None:
    """Save Route 53 Resolver firewall rule group associations for an account and
    region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        firewall_rule_group_associations: The list of Route 53 Resolver firewall rule
        group associations to save.
    """
    _save_data(
        firewall_rule_group_associations,
        f"route53resolver_firewall_rule_group_associations_{region}",
        account_id,
    )


def get_route53resolver_firewall_rule_group_associations(
    account_id: str, region: str
) -> list[dict[str, Any]]:
    """Get Route 53 Resolver firewall rule group associations for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return (
        _load_data(
            f"route53resolver_firewall_rule_group_associations_{region}", account_id
        )
        or []
    )


def save_route53resolver_firewall_domain_lists(
    account_id: str, region: str, firewall_domain_lists: list[dict[str, Any]]
) -> None:
    """Save Route 53 Resolver firewall domain lists for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        firewall_domain_lists: The list of Route 53 Resolver firewall domain lists to
        save.
    """
    _save_data(
        firewall_domain_lists,
        f"route53resolver_firewall_domain_lists_{region}",
        account_id,
    )


def get_route53resolver_firewall_domain_lists(
    account_id: str, region: str
) -> list[dict[str, Any]]:
    """Get Route 53 Resolver firewall domain lists for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return (
        _load_data(f"route53resolver_firewall_domain_lists_{region}", account_id) or []
    )


def save_apigateway_rest_apis(
    account_id: str, region: str, rest_apis: list[dict[str, Any]]
) -> None:
    """Save API Gateway REST APIs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        rest_apis: The list of API Gateway REST APIs to save.
    """
    _save_data(rest_apis, f"apigateway_rest_apis_{region}", account_id)


def get_apigateway_rest_apis(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get API Gateway REST APIs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"apigateway_rest_apis_{region}", account_id) or []


def save_appsync_graphql_apis(
    account_id: str, region: str, graphql_apis: list[dict[str, Any]]
) -> None:
    """Save AppSync GraphQL APIs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        graphql_apis: The list of AppSync GraphQL APIs to save.
    """
    _save_data(graphql_apis, f"appsync_graphql_apis_{region}", account_id)


def get_appsync_graphql_apis(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get AppSync GraphQL APIs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"appsync_graphql_apis_{region}", account_id) or []


def save_cloudfront_distributions(
    account_id: str, distributions: list[dict[str, Any]]
) -> None:
    """Save CloudFront distributions for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        distributions: The list of CloudFront distributions to save.
    """
    _save_data(distributions, "cloudfront_distributions", account_id)


def get_cloudfront_distributions(account_id: str) -> list[dict[str, Any]]:
    """Get CloudFront distributions for an account.

    Args:
        account_id: The AWS account ID.
    """
    return _load_data("cloudfront_distributions", account_id) or []


def save_networkfirewall_firewalls(
    account_id: str, region: str, firewalls: list[dict[str, Any]]
) -> None:
    """Save Network Firewall firewalls for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        firewalls: The list of Network Firewall firewalls to save.
    """
    _save_data(firewalls, f"networkfirewall_firewalls_{region}", account_id)


def get_networkfirewall_firewalls(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get Network Firewall firewalls for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"networkfirewall_firewalls_{region}", account_id) or []


def save_regional_web_acls(
    account_id: str, region: str, web_acls: list[dict[str, Any]]
) -> None:
    """Save regional web ACLs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        web_acls: The list of regional web ACLs to save.
    """
    _save_data(web_acls, f"regional_web_acls_{region}", account_id)


def get_regional_web_acls(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get regional web ACLs for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"regional_web_acls_{region}", account_id) or []


def save_regional_waf_logging_configurations(
    account_id: str, region: str, logging_configurations: list[dict[str, Any]]
) -> None:
    """Save regional WAF logging configurations for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        logging_configurations: The list of regional WAF logging configurations to save.
    """
    _save_data(
        logging_configurations,
        f"regional_waf_logging_configurations_{region}",
        account_id,
    )


def get_regional_waf_logging_configurations(
    account_id: str, region: str
) -> list[dict[str, Any]]:
    """Get regional WAF logging configurations for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"regional_waf_logging_configurations_{region}", account_id) or []


def save_cloudfront_web_acls(account_id: str, web_acls: list[dict[str, Any]]) -> None:
    """Save CloudFront web ACLs for an account.

    Args:
        account_id: The AWS account ID.
        web_acls: The list of CloudFront web ACLs to save.
    """
    _save_data(web_acls, "cloudfront_web_acls", account_id)


def get_cloudfront_web_acls(account_id: str) -> list[dict[str, Any]]:
    """Get CloudFront web ACLs for an account.

    Args:
        account_id: The AWS account ID.
    """
    return _load_data("cloudfront_web_acls", account_id) or []


def save_cloudfront_waf_logging_configurations(
    account_id: str, logging_configurations: list[dict[str, Any]]
) -> None:
    """Save CloudFront WAF logging configurations for an account.

    Args:
        account_id: The AWS account ID.
        logging_configurations: The list of CloudFront WAF logging configurations to
        save.
    """
    _save_data(
        logging_configurations, "cloudfront_waf_logging_configurations", account_id
    )


def get_cloudfront_waf_logging_configurations(account_id: str) -> list[dict[str, Any]]:
    """Get CloudFront WAF logging configurations for an account.

    Args:
        account_id: The AWS account ID.
    """
    return _load_data("cloudfront_waf_logging_configurations", account_id) or []


def save_redshift_clusters(
    account_id: str, region: str, clusters: list[dict[str, Any]]
) -> None:
    """Save Redshift clusters for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        clusters: The list of Redshift clusters to save.
    """
    _save_data(clusters, f"redshift_clusters_{region}", account_id)


def get_redshift_clusters(account_id: str, region: str) -> list[dict[str, Any]]:
    """Get Redshift clusters for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"redshift_clusters_{region}", account_id) or []


def save_sagemaker_notebook_instances(
    account_id: str, region: str, instances: list[dict[str, Any]]
) -> None:
    """Save SageMaker notebook instances for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
        instances: The list of SageMaker notebook instances to save.
    """
    _save_data(instances, f"sagemaker_notebook_instances_{region}", account_id)


def get_sagemaker_notebook_instances(
    account_id: str, region: str
) -> list[dict[str, Any]]:
    """Get SageMaker notebook instances for an account and region.

    Args:
        account_id: The AWS account ID.
        region: The AWS region.
    """
    return _load_data(f"sagemaker_notebook_instances_{region}", account_id) or []
