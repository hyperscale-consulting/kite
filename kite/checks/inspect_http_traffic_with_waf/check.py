"""Check if AWS WAF is used to inspect and block HTTP-based traffic."""

from typing import Any

from kite.config import Config
from kite.data import get_apigateway_rest_apis
from kite.data import get_appsync_graphql_apis
from kite.data import get_cloudfront_distributions
from kite.data import get_elbv2_load_balancers
from kite.data import get_regional_web_acls
from kite.data import get_cloudfront_web_acls
from kite.helpers import get_account_ids_in_scope
from kite.helpers import manual_check

CHECK_ID = "inspect-http-traffic-with-waf"
CHECK_NAME = "Inspect HTTP Traffic with WAF"


def _get_waf_summary() -> tuple[str, dict[str, set[str]]]:
    """Get summary of WAF web ACLs and their attached resources."""
    analysis = ""
    waf_resources = {}  # Map of resource ARNs to WAF ACL names
    accounts = get_account_ids_in_scope()
    regions = Config.get().active_regions

    total_wafs = 0

    for account_id in accounts:
        account_analysis = f"\nAccount: {account_id}\n"
        account_wafs = 0
        account_has_wafs = False

        web_acls = get_cloudfront_web_acls(account_id)

        for region in regions:
            web_acls.extend(get_regional_web_acls(account_id, region))

        if not web_acls:
            continue

        account_has_wafs = True

        for acl in web_acls:
            total_wafs += 1
            account_wafs += 1

            acl_name = acl.get("Name", "Unnamed")
            acl_arn = acl.get("ARN", "Unknown")
            resources = acl.get("Resources", [])

            account_analysis += f"    WAF: {acl_name}\n"
            account_analysis += f"      ARN: {acl_arn}\n"
            account_analysis += f"      Region: {acl.get('Region', 'Unknown')}\n"
            account_analysis += f"      Resources: {len(resources)}\n"

            # Track which resources are protected by this WAF
            for resource_arn in resources:
                waf_resources[resource_arn] = acl_name

            # Summarize rules
            rules = acl.get("Rules", [])
            if rules:
                account_analysis += f"      Rules ({len(rules)}):\n"

                for rule in rules:
                    rule_name = rule.get("Name", "Unnamed")
                    priority = rule.get("Priority", "Unknown")
                    action = _get_rule_action_summary(rule)
                    statement = _get_rule_statement_summary(rule)

                    account_analysis += (
                        f"        - {rule_name} (Priority: {priority})\n"
                    )
                    account_analysis += f"          Action: {action}\n"
                    account_analysis += f"          Type: {statement}\n"
            else:
                account_analysis += "      No rules configured\n"

            account_analysis += "\n"

        # Only include account if it has WAFs
        if account_has_wafs:
            analysis += account_analysis

    if total_wafs == 0:
        analysis = "\nNo WAF web ACLs found in any account or region.\n"

    return analysis, waf_resources


def _get_rule_action_summary(rule: dict[str, Any]) -> str:
    """Get a summary of the rule action."""
    action = rule.get("Action", {})
    override_action = rule.get("OverrideAction", {})

    if "Block" in action:
        return "BLOCK"
    elif "Allow" in action:
        return "ALLOW"
    elif "Count" in action:
        return "COUNT"
    elif "None" in override_action:
        return "OVERRIDE (None)"
    elif "Count" in override_action:
        return "OVERRIDE (Count)"
    else:
        return "Unknown"


def _get_rule_statement_summary(rule: dict[str, Any]) -> str:
    """Get a summary of the rule statement type."""
    statement = rule.get("Statement", {})

    if "RateBasedStatement" in statement:
        rate_stmt = statement["RateBasedStatement"]
        limit = rate_stmt.get("Limit", "Unknown")
        return f"Rate-based (limit: {limit})"
    elif "ManagedRuleGroupStatement" in statement:
        managed_stmt = statement["ManagedRuleGroupStatement"]
        vendor = managed_stmt.get("VendorName", "Unknown")
        name = managed_stmt.get("Name", "Unknown")
        return f"Managed rule group ({vendor}/{name})"
    elif "RuleGroupReferenceStatement" in statement:
        return "Rule group reference"
    elif "IPSetReferenceStatement" in statement:
        return "IP set reference"
    elif "GeoMatchStatement" in statement:
        return "Geo match"
    elif "ByteMatchStatement" in statement:
        return "Byte match"
    elif "RegexPatternSetReferenceStatement" in statement:
        return "Regex pattern"
    elif "SizeConstraintStatement" in statement:
        return "Size constraint"
    elif "XSSMatchStatement" in statement:
        return "XSS match"
    elif "SQLInjectionMatchStatement" in statement:
        return "SQL injection match"
    else:
        return "Other"


def _get_unprotected_resources() -> str:
    """Get list of resources that don't have WAF protection."""
    analysis = ""
    accounts = get_account_ids_in_scope()
    regions = Config.get().active_regions

    # Get all WAF-protected resources
    _, waf_resources = _get_waf_summary()
    protected_arns = set(waf_resources.keys())

    total_unprotected = 0

    for account_id in accounts:
        account_analysis = f"\nAccount: {account_id}\n"
        account_unprotected = 0
        account_has_resources = False

        # Check CloudFront distributions (global resource)
        cloudfront_distributions = get_cloudfront_distributions(account_id)
        if cloudfront_distributions:
            account_has_resources = True
            account_analysis += "  CloudFront Distributions (Global):\n"
            for dist in cloudfront_distributions:
                dist_arn = dist.get("ARN", "")
                if dist_arn and dist_arn not in protected_arns:
                    account_unprotected += 1
                    account_analysis += (
                        f"    ⚠️  CloudFront: {dist.get('DomainName', 'Unknown')}\n"
                    )

        # Check regional resources
        for region in regions:
            region_analysis = f"  Region: {region}\n"
            region_unprotected = 0
            region_has_resources = False

            # Check ELBv2 load balancers
            load_balancers = get_elbv2_load_balancers(account_id, region)
            if load_balancers:
                region_has_resources = True
            for lb in load_balancers:
                lb_arn = lb.get("LoadBalancerArn", "")
                if lb_arn and lb_arn not in protected_arns:
                    region_unprotected += 1
                    region_analysis += (
                        f"    ⚠️  ELBv2: {lb.get('LoadBalancerName', 'Unknown')}\n"
                    )

            # Check API Gateway REST APIs
            rest_apis = get_apigateway_rest_apis(account_id, region)
            if rest_apis:
                region_has_resources = True
            for api in rest_apis:
                api_arn = api.get("ARN", "")
                if api_arn and api_arn not in protected_arns:
                    region_unprotected += 1
                    region_analysis += (
                        f"    ⚠️  API Gateway: {api.get('Name', 'Unknown')}\n"
                    )

            # Check AppSync GraphQL APIs
            graphql_apis = get_appsync_graphql_apis(account_id, region)
            if graphql_apis:
                region_has_resources = True
            for api in graphql_apis:
                api_arn = api.get("ARN", "")
                if api_arn and api_arn not in protected_arns:
                    region_unprotected += 1
                    region_analysis += f"    ⚠️  AppSync: {api.get('Name', 'Unknown')}\n"

            if region_has_resources:
                if region_unprotected > 0:
                    account_analysis += region_analysis
                    account_unprotected += region_unprotected
                else:
                    account_analysis += (
                        f"  Region: {region} - All resources protected\n"
                    )

        # Only include account if it has resources that need WAF protection AND
        # some are unprotected
        if account_has_resources and account_unprotected > 0:
            analysis += account_analysis
            total_unprotected += account_unprotected

    if total_unprotected == 0:
        analysis = "\nAll HTTP resources have WAF protection.\n"
    else:
        analysis += f"\nSummary: {total_unprotected} resources without WAF protection\n"

    return analysis


def _pre_check() -> tuple[bool, dict[str, Any]]:
    """Pre-check function that automatically fails if no WAFs are found."""
    # Check for WAFs across all accounts and regions
    accounts = get_account_ids_in_scope()
    regions = Config.get().active_regions

    total_wafs = 0

    for account_id in accounts:
        web_acls = get_cloudfront_web_acls(account_id)

        for region in regions:
            web_acls.extend(get_regional_web_acls(account_id, region))
            if web_acls:
                total_wafs += len(web_acls)

    if total_wafs == 0:
        msg_parts = [
            "No WAF web ACLs found in any account or region.",
            "This check fails automatically as no WAF protection is configured.",
        ]
        msg = " ".join(msg_parts)
        result = {}
        result["check_id"] = CHECK_ID
        result["check_name"] = CHECK_NAME
        result["status"] = "FAIL"
        details = {}
        details["message"] = msg
        result["details"] = details
        return False, result

    return True, {}


def check_inspect_http_traffic_with_waf() -> dict[str, Any]:
    """Check if AWS WAF is used to inspect and block HTTP-based traffic."""
    waf_analysis, _ = _get_waf_summary()
    unprotected_analysis = _get_unprotected_resources()

    message = (
        "This check helps you confirm whether AWS WAF is used to inspect and "
        "block HTTP-based traffic.\n\n"
        "AWS WAF helps protect your web applications and APIs from common web "
        "exploits and bots that can affect availability, compromise security, "
        "or consume excessive resources.\n\n"
        "Below is a summary of WAF web ACLs and their configurations:\n"
    )
    message += f"{waf_analysis}\n"
    message += "Resources without WAF protection:\n"
    message += f"{unprotected_analysis}"

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=("Do you use AWS WAF to inspect and block HTTP-based traffic?"),
        pass_message=("AWS WAF is used to inspect and block HTTP-based traffic."),
        fail_message=(
            "AWS WAF should be used to inspect and block HTTP-based traffic "
            "for web applications and APIs."
        ),
        default=True,
        pre_check=_pre_check,
    )


check_inspect_http_traffic_with_waf._CHECK_ID = CHECK_ID
check_inspect_http_traffic_with_waf._CHECK_NAME = CHECK_NAME
