"""Check for protection of root CA."""

from typing import Any

from kite.config import Config
from kite.data import get_acm_pca_certificate_authorities
from kite.helpers import get_account_ids_in_scope
from kite.helpers import manual_check

CHECK_ID = "protect-root-ca"
CHECK_NAME = "Protect Root CA"


def get_certificate_authorities() -> list[dict[str, Any]]:
    """
    Get all certificate authorities across all accounts and regions.

    Returns:
        List of unique certificate authorities, deduplicated by ARN.
    """
    # Use a set to track seen ARNs
    seen_arns: set[str] = set()
    unique_authorities = []

    # Get all accounts in scope
    account_ids = get_account_ids_in_scope()

    # Check authorities in each account and region
    for account_id in account_ids:
        for region in Config.get().active_regions:
            authorities = get_acm_pca_certificate_authorities(account_id, region)

            for authority in authorities:
                arn = authority.get("Arn")
                if arn and arn not in seen_arns:
                    seen_arns.add(arn)
                    unique_authorities.append(authority)

    return unique_authorities


def check_protect_root_ca() -> dict[str, Any]:
    """
    Check if the root CA is properly protected.

    This check verifies that:
    1. The use of the root CA is minimized
    2. Intermediate CAs are used for day-to-day operations
    3. The root CA is kept in its own dedicated AWS account

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    # Get all certificate authorities
    authorities = get_certificate_authorities()

    # Build the message with certificate authority information
    message = "This check verifies that the root CA is properly protected.\n\n"

    if authorities:
        message += "Private Certificate Authorities found:\n"
        for authority in authorities:
            message += (
                f"- ARN: {authority.get('Arn')}\n"
                f"  Type: {authority.get('Type')}\n"
                f"  Status: {authority.get('Status')}\n"
                f"  Owner Account: {authority.get('OwnerAccount')}\n\n"
            )
    else:
        message += "No private certificate authorities found.\n\n"

    message += (
        "Consider the following factors:\n"
        "- Is the use of the root CA minimized to only essential operations?\n"
        "- Are intermediate CAs used for day-to-day certificate operations?\n"
        "- Is the root CA kept in its own dedicated AWS account?\n"
        "- Is access to the root CA strictly controlled and monitored?\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is the root CA properly protected with minimal usage, intermediate CAs "
            "for day-to-day operations, and kept in a dedicated AWS account?"
        ),
        pass_message=(
            "The root CA is properly protected with minimal usage, intermediate CAs "
            "for day-to-day operations, and kept in a dedicated AWS account."
        ),
        fail_message=(
            "The root CA should be protected with minimal usage, intermediate CAs "
            "for day-to-day operations, and kept in a dedicated AWS account."
        ),
        default=False,
    )


check_protect_root_ca._CHECK_ID = CHECK_ID
check_protect_root_ca._CHECK_NAME = CHECK_NAME
