"""Check for cross-service confused deputy prevention in S3 bucket policies."""

import json
from typing import Dict, Any
from kite.data import get_bucket_policies
from kite.helpers import get_account_ids_in_scope


# Define check ID and name
CHECK_ID = "cross-service-confused-deputy-prevention"
CHECK_NAME = "Cross-Service Confused Deputy Prevention"


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


def check_cross_service_confused_deputy_prevention() -> Dict[str, Any]:
    """
    Check for S3 bucket policies that could be vulnerable to confused deputy attacks.

    This check identifies S3 bucket policies that:
    1. Allow actions to be performed by service principals
    2. Do not have proper confused deputy protection via conditions on:
       - aws:SourceAccount
       - aws:SourceArn
       - aws:SourceOrgID
       - aws:SourceOrgPaths

    Returns:
        Dictionary containing check results
    """
    vulnerable_buckets = []

    # Get all bucket policies
    for account_id in get_account_ids_in_scope():
        buckets = get_bucket_policies(account_id)

        for bucket in buckets:
            bucket_name = bucket["bucket_name"]
            policy = bucket.get("policy")

            if not policy:
                continue

            try:
                policy_doc = json.loads(policy)
            except json.JSONDecodeError:
                continue

            for statement in policy_doc.get("Statement", []):
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
                    vulnerable_buckets.append({
                        "account_id": account_id,
                        "bucket_name": bucket_name,
                        "statement": statement
                    })

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "FAIL" if vulnerable_buckets else "PASS",
        "details": {
            "vulnerable_buckets": vulnerable_buckets,
            "message": (
                f"Found {len(vulnerable_buckets)} S3 buckets with policies that could be "
                "vulnerable to confused deputy attacks. These policies allow actions to be "
                "performed by service principals without proper source account/ARN/organization "
                "conditions."
            )
        }
    }


# Attach the check ID and name to the function
check_cross_service_confused_deputy_prevention._CHECK_ID = CHECK_ID
check_cross_service_confused_deputy_prevention._CHECK_NAME = CHECK_NAME
