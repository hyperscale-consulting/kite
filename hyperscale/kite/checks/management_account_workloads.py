from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_bucket_metadata
from hyperscale.kite.data import get_cloudfront_distributions
from hyperscale.kite.data import get_dynamodb_tables
from hyperscale.kite.data import get_ec2_instances
from hyperscale.kite.data import get_ecs_clusters
from hyperscale.kite.data import get_eks_clusters
from hyperscale.kite.data import get_kms_keys
from hyperscale.kite.data import get_lambda_functions
from hyperscale.kite.data import get_rds_instances
from hyperscale.kite.data import get_redshift_clusters
from hyperscale.kite.data import get_sagemaker_notebook_instances
from hyperscale.kite.data import get_sns_topics
from hyperscale.kite.data import get_sqs_queues


class ManagementAccountWorkloadsCheck:
    def __init__(self):
        self.check_id = "no-management-account-workloads"
        self.check_name = "No Management Account Workloads"

    @property
    def question(self) -> str:
        return "Is the management account free of workload resources?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that there are no workloads running in the management "
            "account."
        )

    def _get_workload_resources(
        self, mgmt_account_id: str
    ) -> dict[str, dict[str, list[str]]]:
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

    def _resources_exist(
        self, workload_resources: dict[str, dict[str, list[str]]]
    ) -> bool:
        for region in workload_resources:
            for resource_type in workload_resources[region]:
                if workload_resources[region][resource_type]:
                    return True
        return False

    def _resource_details(self, resource: dict) -> dict:
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

    def run(self) -> CheckResult:
        config = Config.get()
        mgmt_account_id = config.management_account_id
        if not mgmt_account_id:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="No management account ID provided in config, skipping check.",
            )
        workload_resources = self._get_workload_resources(mgmt_account_id)
        if not self._resources_exist(workload_resources):
            return CheckResult(
                status=CheckStatus.PASS,
                reason="No workload resources found in the management account.",
            )
        message = (
            "Workloads should be placed in dedicated workload accounts, not the "
            "management account. This is because:\n"
            "- SCPs and RCPs do not apply to the management account.\n"
            "- Keeping workloads out of the management account helps to restrict "
            "access.\n\n"
            "Consider the following factors for management account workloads:\n"
            "- Are there any workloads running in the management account?\n"
            "- If so, are there valid reasons for these workloads to be in the "
            "management account?\n"
            "- Could these workloads be moved to a dedicated workload account?\n"
        )
        formatted_resources = []
        for region in workload_resources:
            for resource_type in workload_resources[region]:
                for resource in workload_resources[region][resource_type]:
                    if not isinstance(resource, dict):
                        continue
                    resource_str = f"{resource_type}: ({region})"
                    details = self._resource_details(resource)
                    if details:
                        details_str = ", ".join(f"{k}={v}" for k, v in details.items())
                        resource_str += f" ({details_str})"
                    formatted_resources.append(resource_str)
        if formatted_resources:
            message += (
                "\nThe following workload resources were found in the "
                "management account:\n"
            )
            for resource in formatted_resources:
                message += f"- {resource}\n"
        # Always manual, user must confirm
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
