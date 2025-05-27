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


def has_source_org_id_condition(
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


def has_source_account_condition(
    conditions: Dict[str, Any],
    expected_value: str = "false",
    condition_type: str = "Null"
) -> bool:
    """
    Check if conditions have the required aws:SourceAccount condition.

    Args:
        conditions: The conditions dictionary from a policy statement
        expected_value: The expected value (default: "false")
        condition_type: The type of condition to check (default: Null)

    Returns:
        True if the condition exists and matches, False otherwise
    """
    value = get_case_insensitive_value(
        conditions, condition_type, "aws:SourceAccount"
    )
    return value == expected_value


def has_principal_is_aws_service_condition(
    conditions: Dict[str, Any],
    expected_value: str = "true",
    condition_type: str = "Bool"
) -> bool:
    """
    Check if conditions have the required aws:PrincipalIsAWSService condition.

    Args:
        conditions: The conditions dictionary from a policy statement
        expected_value: The expected value (default: "true")
        condition_type: The type of condition to check (default: Bool)

    Returns:
        True if the condition exists and matches, False otherwise
    """
    value = get_case_insensitive_value(
        conditions, condition_type, "aws:PrincipalIsAWSService"
    )
    return value == expected_value


def has_source_ip_condition(
    conditions: Dict[str, Any],
    condition_type: str = "NotIpAddressIfExists"
) -> bool:
    """
    Check if conditions have the required aws:SourceIp condition.

    Args:
        conditions: The conditions dictionary from a policy statement
        condition_type: The type of condition to check (default:
            NotIpAddressIfExists)

    Returns:
        True if the condition exists and has a non-empty list of IPs, False
        otherwise
    """
    value = get_case_insensitive_value(
        conditions, condition_type, "aws:SourceIp"
    )
    return isinstance(value, list) and len(value) > 0


def has_source_vpc_condition(
    conditions: Dict[str, Any],
    condition_type: str = "StringNotEqualsIfExists"
) -> bool:
    """
    Check if conditions have the required aws:SourceVpc condition.

    Args:
        conditions: The conditions dictionary from a policy statement
        condition_type: The type of condition to check (default:
            StringNotEqualsIfExists)

    Returns:
        True if the condition exists and has a non-empty list of VPCs, False
        otherwise
    """
    value = get_case_insensitive_value(
        conditions, condition_type, "aws:SourceVpc"
    )
    return isinstance(value, list) and len(value) > 0


def has_principal_arn_condition(
    conditions: Dict[str, Any],
    condition_type: str = "ArnNotLikeIfExists"
) -> bool:
    """
    Check if conditions have the required aws:PrincipalArn condition.

    Args:
        conditions: The conditions dictionary from a policy statement
        condition_type: The type of condition to check (default:
            ArnNotLikeIfExists)

    Returns:
        True if the condition exists and has a non-empty list of ARNs, False
        otherwise
    """
    value = get_case_insensitive_value(
        conditions, condition_type, "aws:PrincipalArn"
    )
    return isinstance(value, list) and len(value) > 0
