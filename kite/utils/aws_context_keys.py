"""Utility functions for handling AWS context keys in a case-insensitive way."""

from typing import Any, Dict, Optional


def get_case_insensitive_value(
    conditions: Dict[str, Any],
    condition_type: str,
    context_key: str
) -> Optional[Any]:
    """
    Get a value from conditions dictionary in a case-insensitive way.

    Args:
        conditions: The conditions dictionary from a policy statement
        condition_type: The type of condition (e.g., "StringNotEqualsIfExists",
            "Bool", etc.)
        context_key: The context key to look for (e.g., "aws:SourceOrgID")

    Returns:
        The value if found, None otherwise
    """
    if not isinstance(conditions, dict):
        return None

    condition_dict = conditions.get(condition_type, {})
    if not isinstance(condition_dict, dict):
        return None

    # Try exact match first
    if context_key in condition_dict:
        return condition_dict[context_key]

    # Try case-insensitive match
    context_key_lower = context_key.lower()
    for key, value in condition_dict.items():
        if key.lower() == context_key_lower:
            return value

    return None


def has_not_source_org_id_condition(
    conditions: Dict[str, Any],
    org_id: str,
    condition_type: str = "StringNotEqualsIfExists"
) -> bool:
    """
    Check if conditions have the required aws:SourceOrgID condition.

    Args:
        conditions: The conditions dictionary from a policy statement
        org_id: The organization ID to check against
        condition_type: The type of condition to check (default:
            StringNotEqualsIfExists)

    Returns:
        True if the condition exists and matches, False otherwise
    """
    value = get_case_insensitive_value(
        conditions, condition_type, "aws:SourceOrgID"
    )
    return value == org_id


def has_not_resource_org_id_condition(
    conditions: Dict[str, Any],
    org_id: str
) -> bool:
    """
    Check if the 'not resource org ID condition' is present.

    Args:
        conditions: The conditions dictionary from a policy statement
        org_id: The organization ID to check against

    Returns:
        True if the condition exists and matches, False otherwise
    """
    value = get_case_insensitive_value(
        conditions, "StringNotEqualsIfExists", "aws:ResourceOrgID"
    )
    return value == org_id


def has_resource_org_id_condition(
    conditions: Dict[str, Any],
    org_id: str,
    condition_type: str = "StringEquals"
) -> bool:
    """
    Check if conditions have the required aws:ResourceOrgID condition.

    Args:
        conditions: The conditions dictionary from a policy statement
        org_id: The organization ID to check against
        condition_type: The type of condition to check (default: StringEquals)

    Returns:
        True if the condition exists and matches, False otherwise
    """
    value = get_case_insensitive_value(
        conditions, condition_type, "aws:ResourceOrgID"
    )
    return value == org_id


def has_no_source_account_condition(
    conditions: Dict[str, Any]
) -> bool:
    """
    Check if the 'no source account' condition is present.

    Args:
        conditions: The conditions dictionary from a policy statement

    Returns:
        True if the condition exists and matches, False otherwise
    """
    value = get_case_insensitive_value(
        conditions, "Null", "aws:SourceAccount"
    )
    return value == "false"


def has_principal_is_aws_service_condition(
    conditions: Dict[str, Any]
) -> bool:
    """
    Check if the 'principal is AWS service' condition is present.

    Args:
        conditions: The conditions dictionary from a policy statement
        expected_value: The expected value (default: "true")
        condition_type: The type of condition to check (default: Bool)

    Returns:
        True if the condition exists and matches, False otherwise
    """
    value = get_case_insensitive_value(
        conditions, "Bool", "aws:PrincipalIsAWSService"
    )
    return value == "true"


def has_not_source_ip_condition(
    conditions: Dict[str, Any]
) -> bool:
    """
    Check if there is a NotIpAddressIfExists condition on source IP.

    Args:
        conditions: The conditions dictionary from a policy statement

    Returns:
        True if the condition exists and has a non-empty list of IPs, False
        otherwise
    """
    value = get_case_insensitive_value(
        conditions, "NotIpAddressIfExists", "aws:SourceIp"
    )
    return isinstance(value, list) and len(value) > 0


def has_not_source_vpc_condition(
    conditions: Dict[str, Any]
) -> bool:
    """
    Check if conditions have the required aws:SourceVpc condition.

    Args:
        conditions: The conditions dictionary from a policy statement

    Returns:
        True if the condition exists and has a non-empty list of VPCs, False
        otherwise
    """
    value = get_case_insensitive_value(
        conditions, "StringNotEqualsIfExists", "aws:SourceVpc"
    )
    return isinstance(value, list) and len(value) > 0


def has_not_principal_arn_condition(
    conditions: Dict[str, Any],
) -> bool:
    """
    Check if conditions have the required aws:PrincipalArn condition.

    Args:
        conditions: The conditions dictionary from a policy statement

    Returns:
        True if the condition exists and has a non-empty list of ARNs, False
        otherwise
    """
    value = get_case_insensitive_value(
        conditions, "ArnNotLikeIfExists", "aws:PrincipalArn"
    )
    return isinstance(value, list) and len(value) > 0
