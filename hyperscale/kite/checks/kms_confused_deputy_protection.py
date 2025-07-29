from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.conditions import has_confused_deputy_protection
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_kms_keys
from hyperscale.kite.helpers import get_account_ids_in_scope


class KmsConfusedDeputyProtectionCheck:
    def __init__(self):
        self.check_id = "kms-confused-deputy-protection"
        self.check_name = "KMS Key Confused Deputy Protection"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check identifies KMS key policies that allow actions to be "
            "performed by service principals without proper confused deputy protection "
            "via conditions on aws:SourceAccount, aws:SourceArn, aws:SourceOrgID, or "
            "aws:SourceOrgPaths."
        )

    def _is_service_principal(self, principal) -> bool:
        if isinstance(principal, list):
            return any(self._is_service_principal(p) for p in principal)
        if not isinstance(principal, str):
            return False
        return principal.endswith(".amazonaws.com")

    def run(self) -> CheckResult:
        vulnerable_keys = []
        config = Config.get()
        for account_id in get_account_ids_in_scope():
            for region in config.active_regions:
                keys = get_kms_keys(account_id, region)
                for key in keys:
                    key_arn = key["Arn"]
                    policy = key.get("Policy")
                    if not policy:
                        continue
                    for statement in policy.get("Statement", []):
                        if statement.get("Effect") == "Deny":
                            continue
                        if has_confused_deputy_protection(
                            statement.get("Condition", {})
                        ):
                            continue
                        principals = []
                        if "Principal" in statement:
                            if isinstance(statement["Principal"], dict):
                                principals.extend(statement["Principal"].values())
                            elif isinstance(statement["Principal"], str):
                                principals.append(statement["Principal"])
                        if any(self._is_service_principal(p) for p in principals):
                            vulnerable_keys.append(
                                {
                                    "account_id": account_id,
                                    "region": region,
                                    "key_arn": key_arn,
                                    "statement": statement,
                                }
                            )
        if not vulnerable_keys:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=("No KMS keys with confused deputy vulnerabilities found."),
            )
        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                f"Found {len(vulnerable_keys)} KMS keys with policies that could be "
                "vulnerable to confused deputy attacks. These policies allow actions "
                "to be performed by service principals without proper source "
                "account/ARN/organization conditions."
            ),
            details={
                "vulnerable_keys": vulnerable_keys,
            },
        )
