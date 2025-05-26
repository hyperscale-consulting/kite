"""Check for monitoring and response to S3 public access."""

from typing import Dict, Any, List

from kite.helpers import get_account_ids_in_scope, manual_check
from kite.data import get_config_rules


CHECK_ID = "monitor-and-respond-to-s3-public-access"
CHECK_NAME = "Monitor and Respond to S3 Public Access"


def _check_config_rules(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Check if the required Config rules are present and properly configured.

    Args:
        rules: List of Config rules to check

    Returns:
        Dict containing:
            - has_read_rule: bool indicating if S3_BUCKET_PUBLIC_READ_PROHIBITED rule
              exists
            - has_write_rule: bool indicating if S3_BUCKET_PUBLIC_WRITE_PROHIBITED rule
              exists
            - read_rule_has_remediation: bool indicating if read rule has remediation
            - write_rule_has_remediation: bool indicating if write rule has remediation
    """
    result = {
        "has_read_rule": False,
        "has_write_rule": False,
        "read_rule_has_remediation": False,
        "write_rule_has_remediation": False,
    }

    for rule in rules:
        source = rule.get("Source", {})
        source_identifier = source.get("SourceIdentifier", "")
        owner = source.get("Owner", "")

        # Only check AWS managed rules
        if owner != "AWS":
            continue

        # Check if rule applies to all S3 buckets
        scope = rule.get("Scope", {})
        if not (
            len(scope) == 1
            and "ComplianceResourceTypes" in scope
            and scope["ComplianceResourceTypes"] == ["AWS::S3::Bucket"]
        ):
            continue

        if source_identifier == "S3_BUCKET_PUBLIC_READ_PROHIBITED":
            result["has_read_rule"] = True
            result["read_rule_has_remediation"] = bool(
                rule.get("RemediationConfigurations")
            )

        elif source_identifier == "S3_BUCKET_PUBLIC_WRITE_PROHIBITED":
            result["has_write_rule"] = True
            result["write_rule_has_remediation"] = bool(
                rule.get("RemediationConfigurations")
            )

    return result


def check_monitor_and_response_to_s3_public_access() -> Dict[str, Any]:
    """
    Check if there is proper monitoring and response to S3 public access.

    This check verifies that:
    1. Each account has the AWS managed Config rules:
       - S3_BUCKET_PUBLIC_READ_PROHIBITED
       - S3_BUCKET_PUBLIC_WRITE_PROHIBITED
    2. These rules have remediation configurations set up
    3. Asks the user to confirm if monitoring, alerting, and auto-remediation is set up

    Returns:
        A dictionary containing the check results.
    """
    accounts_without_rules = []
    accounts_without_remediation = []

    # Check each account
    for account_id in get_account_ids_in_scope():
        rules = get_config_rules(account_id)
        rule_status = _check_config_rules(rules)

        # Check if both rules exist
        if not (rule_status["has_read_rule"] and rule_status["has_write_rule"]):
            accounts_without_rules.append(account_id)
            continue

        # Check if both rules have remediation
        if not (
            rule_status["read_rule_has_remediation"] and
            rule_status["write_rule_has_remediation"]
        ):
            accounts_without_remediation.append(account_id)

    # Build message for manual check
    message = "S3 Public Access Monitoring and Response:\n\n"

    if accounts_without_rules:
        message += "Accounts missing required Config rules:\n"
        for account_id in accounts_without_rules:
            message += f"- {account_id}\n"
        message += "\n"

    if accounts_without_remediation:
        message += "Accounts with rules but no remediation configuration:\n"
        for account_id in accounts_without_remediation:
            message += f"- {account_id}\n"
        message += "\n"

    message += (
        "Please confirm that the following are in place:\n"
        "1. Monitoring of S3 bucket public access settings\n"
        "2. Alerting when public access is detected\n"
        "3. Automated remediation of public access settings\n"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt="Is monitoring, alerting, and auto-remediation set up for S3 buckets?",
        pass_message="S3 public access monitoring and response is properly configured",
        fail_message="S3 public access monitoring and response needs to be configured",
        default=True,
    )


check_monitor_and_response_to_s3_public_access._CHECK_ID = CHECK_ID
check_monitor_and_response_to_s3_public_access._CHECK_NAME = CHECK_NAME
