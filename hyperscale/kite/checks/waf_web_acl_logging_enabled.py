from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_cloudfront_waf_logging_configurations
from hyperscale.kite.data import get_cloudfront_web_acls
from hyperscale.kite.data import get_regional_waf_logging_configurations
from hyperscale.kite.data import get_regional_web_acls
from hyperscale.kite.helpers import get_account_ids_in_scope


class WafWebAclLoggingEnabledCheck:
    def __init__(self):
        self.check_id = "waf-web-acl-logging-enabled"
        self.check_name = "WAF Web ACL Logging Enabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return "This check verifies that logging is enabled for all WAF Web ACLs."

    def run(self) -> CheckResult:
        config = Config.get()
        web_acls_without_logging = []
        web_acls_with_logging = []

        # Get all in-scope accounts
        accounts = get_account_ids_in_scope()

        # Check each account in each active region
        for account in accounts:
            web_acls = get_cloudfront_web_acls(account)
            logging_configs = get_cloudfront_waf_logging_configurations(account)

            for region in config.active_regions:
                # Get web ACLs and logging configurations for this account and region
                web_acls.extend(get_regional_web_acls(account, region))
                logging_configs.extend(
                    get_regional_waf_logging_configurations(account, region)
                )

            # Create a set of web ACL ARNs that have logging enabled
            logging_enabled_arns = {config["ResourceArn"] for config in logging_configs}

            # Check each web ACL
            for web_acl in web_acls:
                web_acl_arn = web_acl.get("ARN")
                if not web_acl_arn:
                    continue

                web_acl_info = (
                    f"Web ACL: {web_acl.get('Name', 'Unknown')} "
                    f"(Account: {account}, Region: "
                    f"{web_acl.get('Region', 'Unknown')})"
                )

                if web_acl_arn in logging_enabled_arns:
                    web_acls_with_logging.append(web_acl_info)
                else:
                    web_acls_without_logging.append(web_acl_info)

        # Build the message
        message = ""

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
                + "\n".join(
                    f"  - {web_acl}" for web_acl in sorted(web_acls_with_logging)
                )
                + "\n\n"
            )

        if not web_acls_without_logging and not web_acls_with_logging:
            message += "No WAF Web ACLs found in any account or region.\n\n"

        # Determine status based on whether any Web ACLs are missing logging
        if web_acls_without_logging:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="Some WAF Web ACLs do not have logging enabled",
                context=message,
            )
        else:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="All WAF Web ACLs have logging enabled",
                context=message,
            )
