"""Check for auto-remediation of non-compliant resources."""

from typing import Dict, Any

from kite.helpers import get_account_ids_in_scope, manual_check
from kite.data import get_config_rules, get_securityhub_action_targets
from kite.config import Config


CHECK_ID = "auto-remediate-non-compliant-resources"
CHECK_NAME = "Auto-Remediate Non-Compliant Resources"


def check_auto_remediate_non_compliant_resources() -> Dict[str, Any]:
    """
    Check for mechanisms to identify and automatically remediate non-compliant resource
    configurations.

    This check lists:
    1. All Config rules with non-empty RemediationConfiguration attribute
    2. All Security Hub action targets

    Returns:
        Dictionary containing check results
    """
    config = Config.get()
    config_rules_with_remediation = []
    security_hub_action_targets = []

    # Get all account IDs in scope
    for account_id in get_account_ids_in_scope():
        for region in config.active_regions:
            # Get Config rules with remediation
            rules = get_config_rules(account_id, region)
            for rule in rules:
                if rule.get("RemediationConfigurations"):
                    config_rules_with_remediation.append({
                        "account_id": account_id,
                        "region": region,
                        "name": rule.get("ConfigRuleName"),
                        "description": rule.get("Description", "")
                    })

            # Get Security Hub action targets
            targets = get_securityhub_action_targets(account_id, region)
            for target in targets:
                security_hub_action_targets.append({
                    "account_id": account_id,
                    "region": region,
                    "name": target.get("Name"),
                    "description": target.get("Description", "")
                })

    # Format the message with the findings
    message = "The following mechanisms for auto-remediation were found:\n\n"

    if config_rules_with_remediation:
        message += "AWS Config Rules with Remediation Configuration:\n"
        for rule in config_rules_with_remediation:
            message += (
                f"- Account: {rule['account_id']}, Region: {rule['region']}\n"
                f"  Name: {rule['name']}\n"
            )
            if rule['description']:
                message += f"  Description: {rule['description']}\n"
        message += "\n"

    if security_hub_action_targets:
        message += "Security Hub Action Targets:\n"
        for target in security_hub_action_targets:
            message += (
                f"- Account: {target['account_id']}, Region: {target['region']}\n"
                f"  Name: {target['name']}\n"
            )
            if target['description']:
                message += f"  Description: {target['description']}\n"
        message += "\n"

    if not config_rules_with_remediation and not security_hub_action_targets:
        message += "No auto-remediation mechanisms were found.\n\n"

    message += (
        "Consider the following factors:\n"
        "- Are there mechanisms in place to identify non-compliant resource "
        "configurations?\n"
        "- Are there automated remediation processes for common non-compliant "
        "configurations?\n"
        "- Are remediation actions logged and auditable?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Are there mechanisms in place to identify and automatically remediate "
            "non-compliant resource configurations?"
        ),
        pass_message=(
            "Mechanisms are in place to identify and automatically remediate "
            "non-compliant resource configurations."
        ),
        fail_message=(
            "No mechanisms are in place to identify and automatically remediate "
            "non-compliant resource configurations."
        ),
        default=True,
    )


check_auto_remediate_non_compliant_resources._CHECK_ID = CHECK_ID
check_auto_remediate_non_compliant_resources._CHECK_NAME = CHECK_NAME
