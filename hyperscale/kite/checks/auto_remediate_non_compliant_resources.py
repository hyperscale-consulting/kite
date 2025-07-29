from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_config_rules
from hyperscale.kite.data import get_securityhub_action_targets
from hyperscale.kite.helpers import get_account_ids_in_scope


class AutoRemediateNonCompliantResourcesCheck:
    def __init__(self):
        self.check_id = "auto-remediate-non-compliant-resources"
        self.check_name = "Auto-Remediate Non-Compliant Resources"

    @property
    def question(self) -> str:
        return (
            "Are there mechanisms in place to identify and automatically remediate "
            "non-compliant resource configurations?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there are mechanisms in place to identify "
            "non-compliant resource configurations and automatically remediate them, "
            "for example Config Rules with remediation configurations or Security "
            "Hub action targets."
        )

    def run(self) -> CheckResult:
        config = Config.get()
        config_rules_with_remediation = []
        security_hub_action_targets = []
        for account_id in get_account_ids_in_scope():
            for region in config.active_regions:
                rules = get_config_rules(account_id, region)
                for rule in rules:
                    if rule.get("RemediationConfigurations"):
                        config_rules_with_remediation.append(
                            {
                                "account_id": account_id,
                                "region": region,
                                "name": rule.get("ConfigRuleName"),
                                "description": rule.get("Description", ""),
                            }
                        )
                targets = get_securityhub_action_targets(account_id, region)
                for target in targets:
                    security_hub_action_targets.append(
                        {
                            "account_id": account_id,
                            "region": region,
                            "name": target.get("Name"),
                            "description": target.get("Description", ""),
                        }
                    )
        message = "The following mechanisms for auto-remediation were found:\n\n"
        if config_rules_with_remediation:
            message += "AWS Config Rules with Remediation Configuration:\n"
            for rule in config_rules_with_remediation:
                message += (
                    f"- Account: {rule['account_id']}, Region: {rule['region']}\n"
                    f"  Name: {rule['name']}\n"
                )
                if rule["description"]:
                    message += f"  Description: {rule['description']}\n"
            message += "\n"
        if security_hub_action_targets:
            message += "Security Hub Action Targets:\n"
            for target in security_hub_action_targets:
                message += (
                    f"- Account: {target['account_id']}, Region: {target['region']}\n"
                    f"  Name: {target['name']}\n"
                )
                if target["description"]:
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
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
            details={
                "config_rules_with_remediation": config_rules_with_remediation,
                "security_hub_action_targets": security_hub_action_targets,
            },
        )
