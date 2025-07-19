"""AWS Organizations usage check module."""

from kite.data import get_organization

CHECK_ID = "aws-organizations-usage"
CHECK_NAME = "AWS Organizations Usage"


def check_aws_organizations_usage() -> dict:
    """
    Check if AWS Organizations is being used for account management.

    Returns:
        A dictionary containing the finding for the AWS Organizations Usage check.
    """
    org = get_organization()

    if org is None:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": (
                    "AWS Organizations is not being used for account management."
                ),
            },
        }
    else:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "master_account_id": org.master_account_id,
                "arn": org.arn,
                "feature_set": org.feature_set,
                "message": ("AWS Organizations is being used for account management."),
            },
        }


# Attach the check ID and name to the function
check_aws_organizations_usage._CHECK_ID = CHECK_ID
check_aws_organizations_usage._CHECK_NAME = CHECK_NAME
