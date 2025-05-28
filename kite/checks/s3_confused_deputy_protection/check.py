"""Check for confused deputy protection in S3 bucket policies."""

import json
from typing import Dict, Any
from kite.data import get_bucket_metadata
from kite.helpers import get_account_ids_in_scope


# Define check ID and name
CHECK_ID = "s3-confused-deputy-protection"
CHECK_NAME = "S3 Bucket Confused Deputy Protection"


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


def has_confused_deputy_protection(condition: Dict[str, Any]) -> bool:
    """
    Check if a resource-based policy statement condition has confused
    deputy protection.
    """
    if "StringEquals" in condition:
        protected_keys = {
            "aws:sourceaccount",
            "aws:sourcearn",
            "aws:sourceorgid",
            "aws:sourceorgpaths"
        }
        provided_keys = set([key.lower() for key in condition["StringEquals"].keys()])
        if any(key in protected_keys for key in provided_keys):
            return True

    if "ArnLike" in condition:
        provided_keys = set([key.lower() for key in condition["ArnLike"].keys()])
        if "aws:sourcearn" in provided_keys:
            return True

    return False


def _has_confused_deputy_protection(statement: Dict[str, Any]) -> bool:
    """
    Check if a policy statement has confused deputy protection.

    Args:
        statement: The policy statement to check

    Returns:
        True if the statement has confused deputy protection, False otherwise
    """
    condition = statement.get("Condition", {})
    return has_confused_deputy_protection(condition)


def check_s3_confused_deputy_protection() -> Dict[str, Any]:
    """
    Check for S3 bucket policies that could be vulnerable to confused deputy attacks.

    This check identifies S3 bucket policies that:
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
    vulnerable_buckets = []

    # Get all bucket policies
    for account_id in get_account_ids_in_scope():
        buckets = get_bucket_metadata(account_id)

        for bucket in buckets:
            bucket_name = bucket["Name"]
            policy = bucket.get("Policy")

            if not policy:
                continue

            try:
                policy_doc = json.loads(policy)
            except json.JSONDecodeError:
                continue

            for statement in policy_doc.get("Statement", []):
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
check_s3_confused_deputy_protection._CHECK_ID = CHECK_ID
check_s3_confused_deputy_protection._CHECK_NAME = CHECK_NAME
