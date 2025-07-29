from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_apigateway_rest_apis
from hyperscale.kite.data import get_appsync_graphql_apis
from hyperscale.kite.data import get_cloudfront_distributions
from hyperscale.kite.data import get_cloudfront_web_acls
from hyperscale.kite.data import get_elbv2_load_balancers
from hyperscale.kite.data import get_regional_web_acls
from hyperscale.kite.helpers import get_account_ids_in_scope


class InspectHttpTrafficWithWafCheck:
    def __init__(self):
        self.check_id = "inspect-http-traffic-with-waf"
        self.check_name = "Inspect HTTP Traffic with WAF"

    @property
    def question(self) -> str:
        return "Do you use AWS WAF to inspect and block HTTP-based traffic?"

    @property
    def description(self) -> str:
        return (
            "This check verifies whether AWS WAF is used to inspect and "
            "block HTTP-based traffic."
        )

    def _get_waf_summary(self) -> tuple[str, dict[str, set[str]]]:
        analysis = ""
        waf_resources = {}
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
                for resource_arn in resources:
                    waf_resources[resource_arn] = acl_name
                rules = acl.get("Rules", [])
                if rules:
                    account_analysis += f"      Rules ({len(rules)}):\n"
                    for rule in rules:
                        rule_name = rule.get("Name", "Unnamed")
                        priority = rule.get("Priority", "Unknown")
                        action = self._get_rule_action_summary(rule)
                        statement = self._get_rule_statement_summary(rule)
                        account_analysis += (
                            f"        - {rule_name} (Priority: {priority})\n"
                        )
                        account_analysis += f"          Action: {action}\n"
                        account_analysis += f"          Type: {statement}\n"
                else:
                    account_analysis += "      No rules configured\n"
                account_analysis += "\n"
            if account_has_wafs:
                analysis += account_analysis
        if total_wafs == 0:
            analysis = "\nNo WAF web ACLs found in any account or region.\n"
        return analysis, waf_resources

    def _get_rule_action_summary(self, rule: dict) -> str:
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

    def _get_rule_statement_summary(self, rule: dict) -> str:
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

    def _get_unprotected_resources(self) -> str:
        analysis = ""
        accounts = get_account_ids_in_scope()
        regions = Config.get().active_regions
        _, waf_resources = self._get_waf_summary()
        protected_arns = set(waf_resources.keys())
        total_unprotected = 0
        for account_id in accounts:
            account_analysis = f"\nAccount: {account_id}\n"
            account_unprotected = 0
            account_has_resources = False
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
            for region in regions:
                region_analysis = f"  Region: {region}\n"
                region_unprotected = 0
                region_has_resources = False
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
                graphql_apis = get_appsync_graphql_apis(account_id, region)
                if graphql_apis:
                    region_has_resources = True
                for api in graphql_apis:
                    api_arn = api.get("ARN", "")
                    if api_arn and api_arn not in protected_arns:
                        region_unprotected += 1
                        region_analysis += (
                            f"    ⚠️  AppSync: {api.get('Name', 'Unknown')}\n"
                        )
                if region_has_resources:
                    if region_unprotected > 0:
                        account_analysis += region_analysis
                        account_unprotected += region_unprotected
                    else:
                        account_analysis += (
                            f"  Region: {region} - All resources protected\n"
                        )
            if account_has_resources and account_unprotected > 0:
                analysis += account_analysis
                total_unprotected += account_unprotected
        if total_unprotected == 0:
            analysis = "\nAll HTTP resources have WAF protection.\n"
        else:
            analysis += (
                f"\nSummary: {total_unprotected} resources without WAF protection\n"
            )
        return analysis

    def _pre_check(self) -> tuple[bool, dict]:
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
            result = {
                "check_id": self.check_id,
                "check_name": self.check_name,
                "status": "FAIL",
                "details": {"message": msg},
            }
            return False, result
        return True, {}

    def run(self) -> CheckResult:
        pre_check_passed, pre_check_result = self._pre_check()
        if not pre_check_passed:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=pre_check_result["details"]["message"],
            )
        waf_analysis, _ = self._get_waf_summary()
        unprotected_analysis = self._get_unprotected_resources()
        message = (
            "AWS WAF helps protect your web applications and APIs from common web "
            "exploits and bots that can affect availability, compromise security, "
            "or consume excessive resources.\n\n"
            "Below is a summary of WAF web ACLs and their configurations:\n"
        )
        message += f"{waf_analysis}\n"
        message += "Resources without WAF protection:\n"
        message += f"{unprotected_analysis}"
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
