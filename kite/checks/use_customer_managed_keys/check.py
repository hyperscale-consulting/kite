"""Check for use of customer managed keys."""

from typing import Dict, Any, List

from kite.helpers import get_prowler_output, manual_check


CHECK_ID = "use-customer-managed-keys"
CHECK_NAME = "Use Customer Managed Keys"


def check_use_customer_managed_keys() -> Dict[str, Any]:
    """
    Check if customer managed keys are used to protect sensitive data.

    This check verifies that customer managed keys are used for sensitive data by
    checking Prowler results for the following check IDs:
    - cloudtrail_kms_encryption_enabled
    - cloudwatch_log_group_kms_encryption_enabled
    - dynamodb_tables_kms_cmk_encryption_enabled
    - eks_cluster_kms_cmk_encryption_in_secrets_enabled

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of resources that failed the check
    """
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

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=("Are customer managed keys used to protect sensitive data?"),
        pass_message=("Customer managed keys are used to protect sensitive data."),
        fail_message=(
            "Customer managed keys should be used to protect sensitive data."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_use_customer_managed_keys._CHECK_ID = CHECK_ID
check_use_customer_managed_keys._CHECK_NAME = CHECK_NAME
