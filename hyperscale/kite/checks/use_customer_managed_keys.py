from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class UseCustomerManagedKeysCheck:
    def __init__(self):
        self.check_id = "use-customer-managed-keys"
        self.check_name = "Use Customer Managed Keys"

    @property
    def question(self) -> str:
        return "Are customer managed keys used to protect sensitive data?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that customer managed keys are used to protect "
            "sensitive data."
        )

    def run(self) -> CheckResult:
        # Get Prowler results
        prowler_results = get_prowler_output()

        # The check IDs we're interested in
        check_ids = [
            "cloudtrail_kms_encryption_enabled",
            "cloudwatch_log_group_kms_encryption_enabled",
            "dynamodb_tables_kms_cmk_encryption_enabled",
            "eks_cluster_kms_cmk_encryption_in_secrets_enabled",
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
                                "region": result.region,
                                "status": result.status,
                                "check_id": check_id,
                            }
                        )

        # Build message for manual check
        message = "Resources Not Using Customer Managed Keys:\n\n"
        if failing_resources:
            for resource in failing_resources:
                message += f"Account: {resource['account_id']}\n"
                message += f"Region: {resource['region']}\n"
                message += f"Resource Name: {resource['resource_name']}\n"
                message += f"Check ID: {resource['check_id']}\n\n"
        else:
            message += "No resources found without customer managed keys\n\n"

        return CheckResult(status=CheckStatus.MANUAL, context=message)
