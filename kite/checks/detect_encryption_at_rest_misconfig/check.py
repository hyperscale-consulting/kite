"""Check for encryption at rest misconfigurations using AWS Config."""

import re
from typing import Dict, Any

from kite.helpers import manual_check, get_account_ids_in_scope
from kite.data import get_config_rules, get_config_compliance_by_rule
from kite.config import Config


CHECK_ID = "detect-encryption-at-rest-misconfig"
CHECK_NAME = "Detect Encryption at Rest Misconfigurations"


def _is_encryption_rule(rule_name: str) -> bool:
    """
    Check if a rule name matches one of the encryption rules we're interested in.

    Args:
        rule_name: The name of the rule to check

    Returns:
        bool: True if the rule name matches one of our encryption rules
    """
    # Remove securityhub- prefix and hex suffix if present
    base_name = re.sub(r"^securityhub-", "", rule_name)
    base_name = re.sub(r"-[a-f0-9]+$", "", base_name)

    return base_name in [
        "api-gw-cache-enabled-and-encrypted",
        "api-gw-cache-encrypted",
        "appsync-cache-ct-encryption-at-rest",
        "appsync-cache-encryption-at-rest",
        "athena-workgroup-encrypted-at-rest",
        "backup-recovery-point-encrypted",
        "cloud-trail-encryption-enabled",
        "cloudwatch-log-group-encrypted",
        "codebuild-project-artifact-encryption",
        "codebuild-project-s3-logs-encrypted",
        "codebuild-report-group-encrypted-at-rest",
        "dax-encryption-enabled",
        "dax-tls-endpoint-encryption",
        "docdb-cluster-encrypted",
        "dynamodb-table-encrypted-kms",
        "dynamodb-table-encryption-enabled",
        "ec2-ebs-encryption-by-default",
        "ec2-spot-fleet-request-ct-encryption-at-rest",
        "ecr-repository-cmk-encryption-enabled",
        "efs-encrypted-check",
        "efs-filesystem-ct-encrypted",
        "eks-cluster-secrets-encrypted",
        "eks-secrets-encrypted",
        "elasticache-repl-grp-encrypted-at-rest",
        "elasticsearch-encrypted-at-rest",
        "elasticsearch-node-to-node-encryption-check",
        "emr-security-configuration-encryption-rest",
        "encrypted-volumes",
        "event-data-store-cmk-encryption-enabled",
        "glue-ml-transform-encrypted-at-rest",
        "kinesis-firehose-delivery-stream-encrypted",
        "kinesis-stream-encrypted",
        "msk-connect-connector-encrypted",
        "neptune-cluster-encrypted",
        "neptune-cluster-snapshot-encrypted",
        "opensearch-encrypted-at-rest",
        "opensearch-node-to-node-encryption-check",
        "rds-cluster-encrypted-at-rest",
        "rds-proxy-tls-encryption",
        "rds-snapshot-encrypted",
        "rds-storage-encrypted",
        "redshift-serverless-namespace-cmk-encryption",
        "s3-bucket-server-side-encryption-enabled",
        "s3-default-encryption-kms",
        "sns-encrypted-kms",
        "sqs-queue-encrypted",
        "workspaces-root-volume-encryption-enabled",
        "workspaces-user-volume-encryption-enabled",
    ]


def check_detect_encryption_at_rest_misconfig() -> Dict[str, Any]:
    """
    Check if AWS Config is used to detect encryption at rest misconfigurations.

    This check verifies that AWS Config rules are configured to detect and
    remediate encryption at rest misconfigurations for:
    - SQS queues
    - RDS instances

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
                - config_rules: List of relevant Config rules and their status
    """
    # Track results by account and region
    results_by_account = {}

    for account_id in get_account_ids_in_scope():
        results_by_account[account_id] = {}

        for region in Config.get().active_regions:
            # Get Config rules and compliance for this account/region
            config_rules = get_config_rules(account_id, region)
            compliance_results = get_config_compliance_by_rule(account_id, region)

            # Create a map of rule names to compliance
            compliance_map = {
                result["ConfigRuleName"]: result["Compliance"]
                for result in compliance_results
            }

            # Track relevant rules for this account/region
            relevant_rules = []

            # Check each rule
            for rule in config_rules:
                if _is_encryption_rule(rule["ConfigRuleName"]):
                    compliance = compliance_map.get(rule["ConfigRuleName"], {})
                    # Skip rules with insufficient data
                    if compliance.get("ComplianceType") == "INSUFFICIENT_DATA":
                        continue

                    relevant_rules.append(
                        {
                            "name": rule["ConfigRuleName"],
                            "compliance": compliance,
                            "auto_remediation": rule.get(
                                "RemediationConfigurations", []
                            ),
                        }
                    )

            if relevant_rules:
                results_by_account[account_id][region] = relevant_rules

    # Build message for manual check
    message = "AWS Config Rules for Encryption at Rest:\n\n"

    if results_by_account:
        for account_id, regions in results_by_account.items():
            message += f"Account: {account_id}\n"

            for region, rules in regions.items():
                message += f"  Region: {region}\n"

                for rule in rules:
                    message += f"    Rule Name: {rule['name']}\n"

                    # Add compliance information
                    if rule["compliance"]:
                        message += "    Compliance:\n"
                        compliance = rule["compliance"]
                        compliance_type = compliance.get("ComplianceType", "N/A")
                        message += f"      Type: {compliance_type}\n"

                    # Add auto remediation information
                    if rule["auto_remediation"]:
                        message += "    Auto Remediation:\n"
                        for remediation in rule["auto_remediation"]:
                            target_id = remediation.get("TargetId", "N/A")
                            message += f"      Target ID: {target_id}\n"
                            target_type = remediation.get("TargetType", "N/A")
                            message += f"      Target Type: {target_type}\n"
                            params = remediation.get("Parameters", {})
                            message += f"      Parameters: {params}\n"
                    else:
                        message += "    Auto Remediation: Not configured\n"

                    message += "\n"
    else:
        message += "No relevant Config rules found\n\n"

    message += (
        "Please review the above and consider:\n"
        "- Are Config rules configured to detect encryption at rest "
        "misconfigurations?\n"
        "- Are alerts configured for non-compliant resources?\n"
        "- Is auto-remediation configured where appropriate?\n"
        "- Are the rules enabled and actively monitoring resources?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is AWS Config used to check that encryption at rest controls are "
            "enabled as required, alerting and automatically remediating where "
            "non-compliance is found?"
        ),
        pass_message=(
            "AWS Config is used to check that encryption at rest controls are "
            "enabled as required, alerting and automatically remediating where "
            "non-compliance is found."
        ),
        fail_message=(
            "AWS Config should be used to check that encryption at rest controls "
            "are enabled as required, alerting and automatically remediating where "
            "non-compliance is found."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_detect_encryption_at_rest_misconfig._CHECK_ID = CHECK_ID
check_detect_encryption_at_rest_misconfig._CHECK_NAME = CHECK_NAME
