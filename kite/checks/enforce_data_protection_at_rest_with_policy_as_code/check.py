"""Check for policy-as-code enforcement of data protection at rest."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "enforce-data-protection-at-rest-with-policy-as-code"
CHECK_NAME = "Enforce Data Protection at Rest with Policy as Code"


def check_enforce_data_protection_at_rest_with_policy_as_code() -> dict[str, Any]:
    """
    Check if policy-as-code evaluation tools are used to enforce data protection at rest.

    This check verifies that policy-as-code evaluation tools (such as CloudFormation
    Guard) are used in CI/CD pipelines to detect and prevent misconfigurations related
    to protecting data at rest.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "Policy as Code for Data Protection at Rest:\n\n"
        "This check verifies that policy-as-code evaluation tools are used to enforce "
        "data protection at rest requirements in CI/CD pipelines.\n\n"
        "Consider the following:\n"
        "- Are tools like CloudFormation Guard used to evaluate infrastructure as code?\n"
        "- Do the policies check for encryption requirements on:\n"
        "  - S3 buckets\n"
        "  - RDS instances\n"
        "  - EBS volumes\n"
        "  - EFS file systems\n"
        "  - DynamoDB tables\n"
        "  - SQS queues\n"
        "  - SNS topics\n"
        "  - CloudWatch Log Groups\n"
        "  - Other data storage services\n"
        "- Are the policies enforced in CI/CD pipelines before deployment?\n"
        "- Are violations blocked from being deployed?\n"
        "- Are developers notified of policy violations?\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are policy-as-code evaluation tools used to detect and prevent "
            "misconfigurations relating to protecting data at rest in CI/CD "
            "pipelines?"
        ),
        pass_message=(
            "Policy-as-code evaluation tools are used to detect and prevent "
            "misconfigurations relating to protecting data at rest in CI/CD "
            "pipelines."
        ),
        fail_message=(
            "Policy-as-code evaluation tools should be used to detect and prevent "
            "misconfigurations relating to protecting data at rest in CI/CD "
            "pipelines."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_enforce_data_protection_at_rest_with_policy_as_code._CHECK_ID = CHECK_ID
check_enforce_data_protection_at_rest_with_policy_as_code._CHECK_NAME = CHECK_NAME
