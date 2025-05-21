"""Check for confused deputy protection in SQS queue policies."""

from typing import Dict, Any
from kite.data import get_sqs_queues
from kite.helpers import get_account_ids_in_scope
from kite.config import Config


# Define check ID and name
CHECK_ID = "sqs-confused-deputy-protection"
CHECK_NAME = "SQS Queue Confused Deputy Protection"


def _is_service_principal(principal: Any) -> bool:
    """
    Check if a principal is a service principal.

    Args:
        principal: The principal to check (can be string or list)

    Returns:
        True if the principal is a service principal, False otherwise
    """
    if isinstance(principal, list):
        return any(_is_service_principal(p) for p in principal)
    if not isinstance(principal, str):
        return False
    return principal.endswith(".amazonaws.com")


def _has_confused_deputy_protection(statement: Dict[str, Any]) -> bool:
    """
    Check if a policy statement has confused deputy protection.

    Args:
        statement: The policy statement to check

    Returns:
        True if the statement has confused deputy protection, False otherwise
    """
    condition = statement.get("Condition", {})

    # Check StringEquals conditions
    if "StringEquals" in condition:
        protected_keys = {
            "aws:SourceAccount",
            "aws:SourceArn",
            "aws:SourceOrgID",
            "aws:SourceOrgPaths"
        }
        if any(key in condition["StringEquals"] for key in protected_keys):
            return True

    # Check ArnLike conditions
    if "ArnLike" in condition and "aws:SourceArn" in condition["ArnLike"]:
        return True

    return False


def check_sqs_confused_deputy_protection() -> Dict[str, Any]:
    """
    Check for SQS queue policies that could be vulnerable to confused deputy attacks.

    This check identifies SQS queue policies that:
    1. Allow actions to be performed by service principals
    2. Do not have proper confused deputy protection via conditions on:
       - aws:SourceAccount
       - aws:SourceArn
       - aws:SourceOrgID
       - aws:SourceOrgPaths

    Note: Only Allow statements are considered vulnerable. Deny statements are
    considered a security control and are not flagged.

    Returns:
        Dictionary containing check results
    """
    vulnerable_queues = []
    config = Config.get()

    # Get all SQS queues
    for account_id in get_account_ids_in_scope():
        for region in config.active_regions:
            queues = get_sqs_queues(account_id, region)

            for queue in queues:
                queue_arn = queue["queue_arn"]
                policy = queue.get("policy")

                if not policy:
                    continue

                for statement in policy.get("Statement", []):
                    # Skip Deny statements as they are a security control
                    if statement.get("Effect") == "Deny":
                        continue

                    # Skip if statement has confused deputy protection
                    if _has_confused_deputy_protection(statement):
                        continue

                    # Check principals in the statement
                    principals = []
                    if "Principal" in statement:
                        if isinstance(statement["Principal"], dict):
                            principals.extend(statement["Principal"].values())
                        elif isinstance(statement["Principal"], str):
                            principals.append(statement["Principal"])

                    # Check if any principal is a service principal
                    if any(_is_service_principal(p) for p in principals):
                        vulnerable_queues.append({
                            "account_id": account_id,
                            "region": region,
                            "queue_arn": queue_arn,
                            "statement": statement
                        })

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL" if vulnerable_queues else "PASS",
        "details": {
            "vulnerable_queues": vulnerable_queues,
            "message": (
                f"Found {len(vulnerable_queues)} SQS queues with policies that could be "
                "vulnerable to confused deputy attacks. These policies allow actions to "
                "be performed by service principals without proper source account/ARN/"
                "organization conditions."
            )
        }
    }


# Attach the check ID and name to the function
check_sqs_confused_deputy_protection._CHECK_ID = CHECK_ID
check_sqs_confused_deputy_protection._CHECK_NAME = CHECK_NAME
