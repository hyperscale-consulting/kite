"""Management account workloads check module."""

from typing import Any

from rich.console import Console

from kite.config import Config
from kite.data import get_bucket_metadata
from kite.data import get_cloudfront_distributions
from kite.data import get_dynamodb_tables
from kite.data import get_ec2_instances
from kite.data import get_ecs_clusters
from kite.data import get_eks_clusters
from kite.data import get_kms_keys
from kite.data import get_lambda_functions
from kite.data import get_rds_instances
from kite.data import get_redshift_clusters
from kite.data import get_sagemaker_notebook_instances
from kite.data import get_sns_topics
from kite.data import get_sqs_queues
from kite.helpers import prompt_user_with_panel

console = Console()


CHECK_ID = "no-management-account-workloads"
CHECK_NAME = "No Management Account Workloads"


def _get_workload_resources(mgmt_account_id: str) -> dict[str, dict[str, list[str]]]:
    results = {}
    for region in Config.get().active_regions:
        results[region] = {}

        results[region]["EC2"] = get_ec2_instances(mgmt_account_id, region)
        results[region]["ECS"] = get_ecs_clusters(mgmt_account_id, region)
        results[region]["EKS"] = get_eks_clusters(mgmt_account_id, region)
        results[region]["Lambda"] = get_lambda_functions(mgmt_account_id, region)
        results[region]["RDS"] = get_rds_instances(mgmt_account_id, region)
        results[region]["DynamoDB"] = get_dynamodb_tables(mgmt_account_id, region)
        results[region]["Redshift"] = get_redshift_clusters(mgmt_account_id, region)
        results[region]["SageMaker"] = get_sagemaker_notebook_instances(
            mgmt_account_id, region
        )
        results[region]["SNS"] = get_sns_topics(mgmt_account_id, region)
        results[region]["SQS"] = get_sqs_queues(mgmt_account_id, region)
        results[region]["KMS"] = get_kms_keys(mgmt_account_id, region)

    results["global"] = {}
    results["global"]["S3"] = get_bucket_metadata(mgmt_account_id)
    results["global"]["CloudFront"] = get_cloudfront_distributions(mgmt_account_id)
    return results


def _resources_exist(workload_resources: dict[str, dict[str, list[str]]]) -> bool:
    for region in workload_resources:
        for resource_type in workload_resources[region]:
            if workload_resources[region][resource_type]:
                return True
    return False


def _resource_details(resource: dict[str, Any]) -> dict[str, Any]:
    for attr in [
        "Name",
        "Id",
        "Arn",
        "ARN",
        "InstanceId",
        "clusterArn",
        "clusterName",
        "TopicArn",
        "QueueUrl",
        "KeyId",
        "FunctionName",
        "DBInstanceIdentifier",
    ]:
        if attr in resource:
            return {attr: resource[attr]}
    return {}


def check_management_account_workloads() -> dict[str, Any]:
    """
    Check if there are workloads running in the management account.

    Args:
        config: The configuration object containing AWS credentials and settings.
               If not provided, it will be retrieved using Config.get().

    Returns:
        A dictionary containing the check results.
    """
    # Get the management account ID
    config = Config.get()

    mgmt_account_id = config.management_account_id

    # If no management account ID is provided, we can pass this check
    if not mgmt_account_id:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": (
                    "No management account ID provided in config, skipping check."
                ),
            },
        }

    # Load the collected workload resources
    workload_resources = _get_workload_resources(mgmt_account_id)

    if not _resources_exist(workload_resources):
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": ("No workload resources found in the management account."),
            },
        }

    # Initialize message with guidance
    message = (
        "This check evaluates if there are workloads running in the management account."
    )

    # Add assessment guidance
    message += "\nConsider the following factors for management account workloads:\n"
    message += "- Are there any workloads running in the management account?\n"
    message += (
        "- If so, are there valid reasons for these workloads to be in"
        " the management account?\n"
    )
    message += "- Could these workloads be moved to a dedicated workload account?\n"

    # Format workload resources for display
    formatted_resources = []
    for region in workload_resources:
        for resource_type in workload_resources[region]:
            for resource in workload_resources[region][resource_type]:
                resource_str = f"{resource_type}: ({region})"
                details = _resource_details(resource)
                if details:
                    details_str = ", ".join(f"{k}={v}" for k, v in details.items())
                    resource_str += f" ({details_str})"
                formatted_resources.append(resource_str)

    # Add workload resources to the message if any were found
    if formatted_resources:
        message += (
            "\nThe following workload resources were found in the management account:\n"
        )
        for resource in formatted_resources:
            message += f"- {resource}\n"

    # Ask user to confirm management account workload status
    prompt = "Is the management account free of workload resources?"
    no_workloads, _ = prompt_user_with_panel(
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        default=False,
    )

    if no_workloads:
        success_msg = (
            "The management account is free of workload resources. "
            "This is the recommended configuration."
        )
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": success_msg,
            },
        }

    fail_msg = (
        "The management account contains workload resources. "
        "Consider moving these resources to a dedicated workload account."
    )
    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL",
        "details": {
            "message": fail_msg,
        },
    }


# Attach the check ID and name to the function
check_management_account_workloads._CHECK_ID = CHECK_ID
check_management_account_workloads._CHECK_NAME = CHECK_NAME
