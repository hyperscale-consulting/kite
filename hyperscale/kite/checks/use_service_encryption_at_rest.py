from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class UseServiceEncryptionAtRestCheck:
    def __init__(self):
        self.check_id = "use-service-encryption-at-rest"
        self.check_name = "Use Service Encryption at Rest"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that encryption at rest is enabled for services "
            "that can be configured with or without encryption."
        )

    def run(self) -> CheckResult:
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
        failing_resources: list[dict[str, str]] = []

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

        if passed:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="All services have encryption at rest enabled.",
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                f"Found {len(failing_resources)} resources without encryption "
                "at rest enabled."
            ),
            details={
                "failing_resources": failing_resources,
            },
        )
