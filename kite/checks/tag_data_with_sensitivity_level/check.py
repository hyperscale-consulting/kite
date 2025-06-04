"""Check for data sensitivity level tagging."""

from typing import Dict, Any, List

from kite.helpers import manual_check
from kite.data import get_organization


CHECK_ID = "tag-data-with-sensitivity-level"
CHECK_NAME = "Tag Data with Sensitivity Level"


def _get_tag_policies(org) -> List[Dict[str, Any]]:
    """
    Get all tag policies in the organization.

    Args:
        org: The organization object

    Returns:
        List of dictionaries containing tag policy information
    """
    tag_policies = []

    def process_ou(ou):
        # Add tag policies from this OU
        for policy in ou.tag_policies:
            tag_policies.append({
                "name": policy.name,
                "description": policy.description,
                "target": f"OU: {ou.name}",
                "content": policy.content
            })

        # Process child OUs
        for child_ou in ou.child_ous:
            process_ou(child_ou)

        # Process accounts in this OU
        for account in ou.accounts:
            for policy in account.tag_policies:
                tag_policies.append({
                    "name": policy.name,
                    "description": policy.description,
                    "target": f"Account: {account.name}",
                    "content": policy.content
                })

    if org:
        process_ou(org.root)
    return tag_policies


def check_tag_data_with_sensitivity_level() -> Dict[str, Any]:
    """
    Check if resource and data-level tagging is used to label data with its
    sensitivity level.

    This check verifies that:
    - Resources are tagged with sensitivity level
    - Data is tagged with sensitivity level
    - Tagging is used for compliance monitoring
    - Tagging is used for incident response

    Returns:
        Dictionary containing check results
    """
    # Get organization data
    org = get_organization()
    tag_policies = _get_tag_policies(org)

    # Format the message with the findings
    message = (
        "This check verifies that resource and data-level tagging is used to "
        "label data with its sensitivity level.\n\n"
        "The tagging should be used for:\n"
        "- Compliance monitoring\n"
        "- Incident response\n\n"
    )

    if tag_policies:
        message += "The following tag policies were found in the organization:\n"
        for policy in tag_policies:
            message += f"- Name: {policy['name']}\n"
            message += f"  Target: {policy['target']}\n"
            if policy['description']:
                message += f"  Description: {policy['description']}\n"
        message += "\n"

    message += (
        "Consider the following factors:\n"
        "- Is tagging consistently applied across all resources?\n"
        "- Are sensitivity levels aligned with the data classification scheme?\n"
        "- Is there a process to maintain and validate tags?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is resource and data-level tagging used to label data with its "
            "sensitivity level to aid compliance, monitoring and incident response?"
        ),
        pass_message=(
            "Resource and data-level tagging is used to label data with its "
            "sensitivity level."
        ),
        fail_message=(
            "Resource and data-level tagging is not used to label data with its "
            "sensitivity level."
        ),
        default=True,
    )


check_tag_data_with_sensitivity_level._CHECK_ID = CHECK_ID
check_tag_data_with_sensitivity_level._CHECK_NAME = CHECK_NAME
