"""Check for absence of secrets in AWS resources."""

from typing import Any

from kite.helpers import get_prowler_output
from kite.helpers import manual_check

CHECK_ID = "no-secrets-in-aws-resources"
CHECK_NAME = "No Secrets in AWS Resources"

# List of prowler checks to verify
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


def check_no_secrets_in_aws_resources() -> dict[str, Any]:
    """
    Check if any AWS resources contain secrets.

    This check verifies that no AWS resources contain secrets by checking the results
    of specific prowler checks that look for secrets in various AWS resources.
    The user can review and confirm if any findings are false positives.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - findings: List of dictionaries containing:
                    - check_id: str
                    - accounts: List of dictionaries containing:
                        - account_id: str
                        - resources: List of dictionaries containing:
                            - resource_uid: str
                            - resource_name: str
                            - resource_details: str
                            - region: str
                            - extended_status: str
    """
    try:
        # Get prowler output
        prowler_results = get_prowler_output()

        # Track failed checks
        failed_checks: list[dict[str, Any]] = []

        # Check each secrets-related prowler check
        for check_id in SECRETS_CHECKS:
            if check_id in prowler_results:
                # Get accounts where this check failed
                failed_accounts = []
                for result in prowler_results[check_id]:
                    if result.status == "FAIL":
                        # Find or create account entry
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

                        # Add resource details
                        account_entry["resources"].append(
                            {
                                "resource_uid": result.resource_uid,
                                "resource_name": result.resource_name,
                                "resource_details": result.resource_details,
                                "region": result.region,
                                "extended_status": result.extended_status,
                            }
                        )

                if failed_accounts:
                    failed_checks.append(
                        {"check_id": check_id, "accounts": failed_accounts}
                    )

        # If no failures found, return PASS
        if not failed_checks:
            return {
                "check_id": CHECK_ID,
                "check_name": CHECK_NAME,
                "status": "PASS",
                "details": {
                    "message": "No secrets found in AWS resources.",
                },
            }

        # Format the findings for display
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
                    findings_message += f"    Details: {resource['resource_details']}\n"
                    findings_message += f"    Status: {resource['extended_status']}\n\n"

        # Use manual_check to get user confirmation
        result = manual_check(
            check_id=CHECK_ID,
            check_name=CHECK_NAME,
            message=(
                "This check verifies that no AWS resources contain secrets.\n\n"
                f"{findings_message}\n"
                "Please review these findings and confirm if they are valid or "
                "false positives."
            ),
            prompt=(
                "After reviewing the findings above, are you happy that there "
                "are no actual secrets in AWS resources?"
            ),
            pass_message=(
                "No actual secrets were found in AWS resources. Any findings were "
                "confirmed as false positives."
            ),
            fail_message=(
                "Potential secrets were found in AWS resources that need to be "
                "addressed."
            ),
            default=True,
        )

        # Add the findings to the result details
        if "details" in result:
            result["details"]["findings"] = failed_checks

        return result

    except Exception as e:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "ERROR",
            "details": {
                "message": f"Error checking for secrets in AWS resources: {str(e)}",
            },
        }


# Attach the check ID and name to the function
check_no_secrets_in_aws_resources._CHECK_ID = CHECK_ID
check_no_secrets_in_aws_resources._CHECK_NAME = CHECK_NAME
