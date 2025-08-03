from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class NoSecretsInAwsResourcesCheck:
    SECRETS_CHECKS = [
        "autoscaling_find_secrets_ec2_launch_configuration",
        "awslambda_function_no_secrets_in_code",
        "awslambda_function_no_secrets_in_variables",
        "cloudformation_stack_outputs_find_secrets",
        "ec2_instance_secrets_user_data",
        "ec2_launch_template_no_secrets",
        "ecs_task_definitions_no_environment_secrets",
        "ssm_document_secrets",
    ]

    def __init__(self):
        self.check_id = "no-secrets-in-aws-resources"
        self.check_name = "No Secrets in AWS Resources"

    @property
    def question(self) -> str:
        return (
            "After reviewing the findings above, are you happy that there "
            "are no actual secrets in AWS resources?"
        )

    @property
    def description(self) -> str:
        return "This check verifies that no AWS resources contain secrets."

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        failed_checks = []
        for check_id in self.SECRETS_CHECKS:
            if check_id in prowler_results:
                failed_accounts = []
                for result in prowler_results[check_id]:
                    if result.status == "FAIL":
                        account_entry = next(
                            (
                                acc
                                for acc in failed_accounts
                                if acc["account_id"] == result.account_id
                            ),
                            None,
                        )
                        if not account_entry:
                            account_entry = {
                                "account_id": result.account_id,
                                "resources": [],
                            }
                            failed_accounts.append(account_entry)
                        account_entry["resources"].append(
                            {
                                "resource_uid": result.resource_uid,
                                "resource_name": result.resource_name,
                                "region": result.region,
                                "extended_status": result.extended_status,
                            }
                        )
                if failed_accounts:
                    failed_checks.append(
                        {"check_id": check_id, "accounts": failed_accounts}
                    )
        if not failed_checks:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="No secrets found in AWS resources.",
            )
        findings_message = (
            "The following potential secrets were found in AWS resources:\n\n"
        )
        for check in failed_checks:
            findings_message += f"Check: {check['check_id']}\n"
            for account in check["accounts"]:
                findings_message += f"  Account: {account['account_id']}\n"
                for resource in account["resources"]:
                    resource_name = (
                        resource["resource_name"] or resource["resource_uid"]
                    )
                    findings_message += f"    Resource: {resource_name}\n"
                    findings_message += f"    Region: {resource['region']}\n"
                    findings_message += f"    Status: {resource['extended_status']}\n\n"
        message = (
            f"{findings_message}\n"
            "Please review these findings and confirm if they are valid or "
            "false positives."
        )
        # Manual check: always require user confirmation
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
            details={
                "findings": failed_checks,
            },
        )
