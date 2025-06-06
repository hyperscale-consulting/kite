"""Check for implementation of data retention policies."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "implement-retention-policies"
CHECK_NAME = "Implement Retention Policies"


def check_implement_retention_policies() -> Dict[str, Any]:
    """
    Check if automated data retention policies are implemented that align with
    legal, regulatory and organizational requirements.

    This check asks the user to confirm that:
    1. Data retention policies are documented and implemented
    2. Policies align with legal and regulatory requirements
    3. Policies align with organizational requirements
    4. Policies are automated where possible

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that automated data retention policies are "
        "implemented that align with legal, regulatory and organizational "
        "requirements."
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are automated data retention policies implemented that align with "
            "legal, regulatory and organizational requirements?"
        ),
        pass_message=(
            "Automated data retention policies are implemented that align with "
            "legal, regulatory and organizational requirements."
        ),
        fail_message=(
            "Automated data retention policies should be implemented that align "
            "with legal, regulatory and organizational requirements."
        ),
        default=True,
    )


check_implement_retention_policies._CHECK_ID = CHECK_ID
check_implement_retention_policies._CHECK_NAME = CHECK_NAME
