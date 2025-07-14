"""Check for WAF Web ACL logging configuration."""

from typing import Any

from kite.config import Config
from kite.data import get_wafv2_logging_configurations
from kite.data import get_wafv2_web_acls
from kite.helpers import get_account_ids_in_scope

CHECK_ID = "waf-web-acl-logging-enabled"
CHECK_NAME = "WAF Web ACL Logging Enabled"


def check_waf_web_acl_logging_enabled() -> dict[str, Any]:
    """
    Check if logging is enabled for all WAF Web ACLs.

    This check:
    1. Gets all WAF Web ACLs in each account and region
    2. Gets all WAF logging configurations in each account and region
    3. Verifies that each Web ACL has a corresponding logging configuration
    4. Fails if any Web ACLs are found without logging enabled

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    config = Config.get()
    web_acls_without_logging = []
    web_acls_with_logging = []

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Check each account in each active region
    for account in accounts:
        for region in config.active_regions:
            # Get web ACLs and logging configurations for this account and region
            web_acls = get_wafv2_web_acls(account, region)
            logging_configs = get_wafv2_logging_configurations(account, region)

            # Create a set of web ACL ARNs that have logging enabled
            logging_enabled_arns = {config["ResourceArn"] for config in logging_configs}

            # Check each web ACL
            for web_acl in web_acls:
                web_acl_arn = web_acl.get("ARN")
                if not web_acl_arn:
                    continue

                web_acl_info = (
                    f"Web ACL: {web_acl.get('Name', 'Unknown')} "
                    f"(Account: {account}, Region: {region})"
                )

                if web_acl_arn in logging_enabled_arns:
                    web_acls_with_logging.append(web_acl_info)
                else:
                    web_acls_without_logging.append(web_acl_info)

    # Build the message
    message = "This check verifies that logging is enabled for all WAF Web ACLs.\n\n"

    if web_acls_without_logging:
        message += (
            "The following WAF Web ACLs do not have logging enabled:\n"
            + "\n".join(
                f"  - {web_acl}" for web_acl in sorted(web_acls_without_logging)
            )
            + "\n\n"
        )

    if web_acls_with_logging:
        message += (
            "The following WAF Web ACLs have logging enabled:\n"
            + "\n".join(f"  - {web_acl}" for web_acl in sorted(web_acls_with_logging))
            + "\n\n"
        )

    if not web_acls_without_logging and not web_acls_with_logging:
        message += "No WAF Web ACLs found in any account or region.\n\n"

    # Determine status based on whether any Web ACLs are missing logging
    if web_acls_without_logging:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": message,
            },
        }
    else:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": message,
            },
        }


# Attach the check ID and name to the function
check_waf_web_acl_logging_enabled._CHECK_ID = CHECK_ID
check_waf_web_acl_logging_enabled._CHECK_NAME = CHECK_NAME
