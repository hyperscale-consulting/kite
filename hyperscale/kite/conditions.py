"""Utility functions for handling AWS context keys in a case-insensitive way."""

from typing import Any


def get_case_insensitive_value(
    conditions: dict[str, Any], condition_type: str, context_key: str
) -> Any | None:
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


def has_not_requested_region_condition(conditions: dict, regions: list) -> bool:
    requested_regions = get_case_insensitive_value(
        conditions, "StringNotEquals", "aws:RequestedRegion"
    )
    if not isinstance(requested_regions, list):
        return False
    return set(regions) == set(requested_regions)


def has_any_account_root_principal_condition(conditions: dict[str, Any]) -> bool:
    root_principal = "arn:*:iam::*:root"
    for condition_type in ["ArnLike", "StringLike"]:
        value = get_case_insensitive_value(
            conditions, condition_type, "aws:PrincipalArn"
        )
        if value:
            if isinstance(value, list):
                for e in value:
                    if e == root_principal:
                        return True
            elif value == root_principal:
                return True
    return False


def has_not_source_org_id_condition(
    conditions: dict[str, Any],
    org_id: str,
    condition_type: str = "StringNotEqualsIfExists",
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
    value = get_case_insensitive_value(conditions, condition_type, "aws:SourceOrgID")
    return value == org_id


def has_not_resource_org_id_condition(conditions: dict[str, Any], org_id: str) -> bool:
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


def has_principal_org_id_condition(conditions: dict[str, Any], org_id: str) -> bool:
    """
    Check if conditions have the required aws:PrincipalOrgID condition.

    Args:
        conditions: The conditions dictionary from a policy statement
        org_id: The organization ID to check against

    Returns:
        True if the condition exists and matches, False otherwise
    """
    value = get_case_insensitive_value(conditions, "StringEquals", "aws:PrincipalOrgID")
    return value == org_id


def has_resource_org_id_condition(
    conditions: dict[str, Any], org_id: str, condition_type: str = "StringEquals"
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
    value = get_case_insensitive_value(conditions, condition_type, "aws:ResourceOrgID")
    return value == org_id


def has_no_source_account_condition(conditions: dict[str, Any]) -> bool:
    """
    Check if the 'no source account' condition is present.

    Args:
        conditions: The conditions dictionary from a policy statement

    Returns:
        True if the condition exists and matches, False otherwise
    """
    value = get_case_insensitive_value(conditions, "Null", "aws:SourceAccount")
    return value == "false"


def has_principal_is_aws_service_condition(conditions: dict[str, Any]) -> bool:
    """
    Check if the 'principal is AWS service' condition is present.

    Args:
        conditions: The conditions dictionary from a policy statement
        expected_value: The expected value (default: "true")
        condition_type: The type of condition to check (default: Bool)

    Returns:
        True if the condition exists and matches, False otherwise
    """
    value = get_case_insensitive_value(conditions, "Bool", "aws:PrincipalIsAWSService")
    return value == "true"


def has_not_source_ip_condition(conditions: dict[str, Any]) -> bool:
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


def has_not_source_vpc_condition(conditions: dict[str, Any]) -> bool:
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
    conditions: dict[str, Any],
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


def has_not_principal_org_id_condition(conditions: dict[str, Any], org_id: str) -> bool:
    """
    Check if conditions have the required aws:PrincipalOrgID condition.

    Args:
        conditions: The conditions dictionary from a policy statement
        org_id: The organization ID to check against
    Returns:
        True if the condition exists and matches, False otherwise
    """
    value = get_case_insensitive_value(
        conditions, "StringNotEqualsIfExists", "aws:PrincipalOrgID"
    )
    return value == org_id


def has_principal_is_not_aws_service_condition(conditions: dict[str, Any]) -> bool:
    value = get_case_insensitive_value(
        conditions, "BoolIfExists", "aws:PrincipalIsAWSService"
    )
    return value == "false"


def has_confused_deputy_protection(condition: dict[str, Any]) -> bool:
    """
    Check if a resource-based policy statement condition has confused
    deputy protection.
    """
    if "StringEquals" in condition:
        protected_keys = {
            "aws:sourceaccount",
            "aws:sourcearn",
            "aws:sourceorgid",
            "aws:sourceorgpaths",
        }
        provided_keys = set([key.lower() for key in condition["StringEquals"].keys()])
        if any(key in protected_keys for key in provided_keys):
            return True

    if "ArnLike" in condition:
        provided_keys = set([key.lower() for key in condition["ArnLike"].keys()])
        if "aws:sourcearn" in provided_keys:
            return True

    return False
