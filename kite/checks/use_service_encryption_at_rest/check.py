"""Check for service encryption at rest."""

from typing import Dict, Any, List

from kite.helpers import get_prowler_output


CHECK_ID = "use-service-encryption-at-rest"
CHECK_NAME = "Use Service Encryption at Rest"


def check_use_service_encryption_at_rest() -> Dict[str, Any]:
    """
    Check if all services have encryption at rest enabled.

    This check verifies that encryption at rest is enabled for services that can be
    configured with or without encryption.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of resources that failed the check
    """
    # Get Prowler results
    prowler_results = get_prowler_output()

    # The check IDs we're interested in
    check_ids = [
        "efs_encryption_at_rest_enabled",
        "opensearch_service_domains_encryption_at_rest_enabled",
        "ec2_ebs_volume_encryption",
        "rds_instance_storage_encrypted",
        "dynamodb_accelerator_cluster_encryption_enabled",
        "ec2_ebs_default_encryption",
        "ec2_ebs_snapshots_encrypted",
        "glue_data_catalogs_connection_passwords_encryption_enabled",
        "glue_data_catalogs_metadata_encryption_enabled",
        "glue_database_connections_ssl_enabled",
        "glue_development_endpoints_cloudwatch_logs_encryption_enabled",
        "glue_development_endpoints_job_bookmark_encryption_enabled",
        "glue_development_endpoints_s3_encryption_enabled",
        "glue_etl_jobs_amazon_s3_encryption_enabled",
        "glue_etl_jobs_cloudwatch_logs_encryption_enabled",
        "glue_etl_jobs_job_bookmark_encryption_enabled",
        "sagemaker_notebook_instance_encryption_enabled",
        "sagemaker_training_jobs_intercontainer_encryption_enabled",
        "sagemaker_training_jobs_volume_and_output_encryption_enabled",
        "sqs_queues_server_side_encryption_enabled",
        "workspaces_volume_encryption_enabled",
    ]

    # Track failing resources
    failing_resources: List[Dict[str, Any]] = []

    # Check results for each check ID
    for check_id in check_ids:
        if check_id in prowler_results:
            # Get results for this check ID
            results = prowler_results[check_id]

            # Add failing resources to the list
            for result in results:
                if result.status != "PASS":
                    failing_resources.append(
                        {
                            "account_id": result.account_id,
                            "resource_uid": result.resource_uid,
                            "resource_name": result.resource_name,
                            "resource_details": result.resource_details,
                            "region": result.region,
                            "status": result.status,
                            "check_id": check_id,
                        }
                    )

    # Determine if the check passed
    passed = len(failing_resources) == 0

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if passed else "FAIL",
        "details": {
            "message": (
                "All services have encryption at rest enabled."
                if passed
                else (
                    f"Found {len(failing_resources)} resources without encryption "
                    "at rest enabled."
                )
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_use_service_encryption_at_rest._CHECK_ID = CHECK_ID
check_use_service_encryption_at_rest._CHECK_NAME = CHECK_NAME
