from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_config_rules
from hyperscale.kite.helpers import get_account_ids_in_scope


class MonitorAndRespondToS3PublicAccessCheck:
    def __init__(self):
        self.check_id = "monitor-and-respond-to-s3-public-access"
        self.check_name = "Monitor and Respond to S3 Public Access"

    @property
    def question(self) -> str:
        return "Is monitoring, alerting, and auto-remediation set up for S3 buckets?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that monitoring, alerting, and auto-remediation are "
            "set up for S3 bucket public access using AWS Config rules and remediation."
        )

    def _check_config_rules(self, rules: list[dict]) -> dict:
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
            if owner != "AWS":
                continue
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

    def run(self) -> CheckResult:
        accounts_without_rules = []
        accounts_without_remediation = []
        for account_id in get_account_ids_in_scope():
            for region in Config.get().active_regions:
                rules = get_config_rules(account_id, region)
                rule_status = self._check_config_rules(rules)
                if not (rule_status["has_read_rule"] and rule_status["has_write_rule"]):
                    accounts_without_rules.append(f"{account_id} ({region})")
                    continue
                if not (
                    rule_status["read_rule_has_remediation"]
                    and rule_status["write_rule_has_remediation"]
                ):
                    accounts_without_remediation.append(f"{account_id} ({region})")
        message = "S3 Public Access Monitoring and Response:\n\n"
        if accounts_without_rules:
            message += "Accounts missing required Config rules:\n"
            for account_and_region in accounts_without_rules:
                message += f"- {account_and_region}\n"
            message += "\n"
        if accounts_without_remediation:
            message += "Accounts with rules but no remediation configuration:\n"
            for account_and_region in accounts_without_remediation:
                message += f"- {account_and_region}\n"
            message += "\n"
        message += (
            "Please confirm that the following are in place:\n"
            "1. Monitoring of S3 bucket public access settings\n"
            "2. Alerting when public access is detected\n"
            "3. Automated remediation of public access settings\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
