"""Check for confused deputy protection in SNS topic policies."""

from typing import Any

from kite.config import Config
from kite.data import get_sns_topics
from kite.helpers import get_account_ids_in_scope
from kite.utils.aws_context_keys import has_confused_deputy_protection

# Define check ID and name
CHECK_ID = "sns-confused-deputy-protection"
CHECK_NAME = "SNS Topic Confused Deputy Protection"


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


def check_sns_confused_deputy_protection() -> dict[str, Any]:
    """
    Check for SNS topic policies that could be vulnerable to confused deputy attacks.

    This check identifies SNS topic policies that:
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
    vulnerable_topics = []
    config = Config.get()

    # Get all SNS topics
    for account_id in get_account_ids_in_scope():
        for region in config.active_regions:
            topics = get_sns_topics(account_id, region)

            for topic in topics:
                topic_arn = topic["topic_arn"]
                policy = topic.get("policy")

                if not policy:
                    continue

                for statement in policy.get("Statement", []):
                    # Skip Deny statements as they are a security control
                    if statement.get("Effect") == "Deny":
                        continue

                    # Skip if statement has confused deputy protection
                    if has_confused_deputy_protection(statement.get("Condition", {})):
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
                        vulnerable_topics.append(
                            {
                                "account_id": account_id,
                                "region": region,
                                "topic_arn": topic_arn,
                                "statement": statement,
                            }
                        )

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL" if vulnerable_topics else "PASS",
        "details": {
            "vulnerable_topics": vulnerable_topics,
            "message": (
                f"Found {len(vulnerable_topics)} SNS topics with policies that could be "
                "vulnerable to confused deputy attacks. These policies allow actions to "
                "be performed by service principals without proper source account/ARN/"
                "organization conditions."
            ),
        },
    }


# Attach the check ID and name to the function
check_sns_confused_deputy_protection._CHECK_ID = CHECK_ID
check_sns_confused_deputy_protection._CHECK_NAME = CHECK_NAME
