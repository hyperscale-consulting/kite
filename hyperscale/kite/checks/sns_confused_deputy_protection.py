from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.conditions import has_confused_deputy_protection
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_sns_topics
from hyperscale.kite.helpers import get_account_ids_in_scope


class SnsConfusedDeputyProtectionCheck:
    def __init__(self):
        self.check_id = "sns-confused-deputy-protection"
        self.check_name = "SNS Topic Confused Deputy Protection"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check identifies SNS topic policies that allow actions to be "
            "performed by service principals without proper confused deputy protection "
            "via conditions on aws:SourceAccount, aws:SourceArn, aws:SourceOrgID, or "
            "aws:SourceOrgPaths."
        )

    def _is_service_principal(self, principal) -> bool:
        """
        Check if a principal is a service principal.

        Args:
            principal: The principal to check (can be string or list)

        Returns:
            True if the principal is a service principal, False otherwise
        """
        if isinstance(principal, list):
            return any(self._is_service_principal(p) for p in principal)
        if not isinstance(principal, str):
            return False
        return principal.endswith(".amazonaws.com")

    def run(self) -> CheckResult:
        vulnerable_topics = []
        config = Config.get()

        # Get all SNS topics
        for account_id in get_account_ids_in_scope():
            for region in config.active_regions:
                topics = get_sns_topics(account_id, region)

                for topic in topics:
                    topic_arn = topic["TopicArn"]
                    policy = topic.get("Policy")

                    if not policy:
                        continue

                    for statement in policy.get("Statement", []):
                        # Skip Deny statements as they are a security control
                        if statement.get("Effect") == "Deny":
                            continue

                        # Skip if statement has confused deputy protection
                        if has_confused_deputy_protection(
                            statement.get("Condition", {})
                        ):
                            continue

                        # Check principals in the statement
                        principals = []
                        if "Principal" in statement:
                            if isinstance(statement["Principal"], dict):
                                principals.extend(statement["Principal"].values())
                            elif isinstance(statement["Principal"], str):
                                principals.append(statement["Principal"])

                        # Check if any principal is a service principal
                        if any(self._is_service_principal(p) for p in principals):
                            vulnerable_topics.append(
                                {
                                    "account_id": account_id,
                                    "region": region,
                                    "topic_arn": topic_arn,
                                    "statement": statement,
                                }
                            )

        if not vulnerable_topics:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="All SNS topic policies have proper confused deputy protection.",
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                f"Found {len(vulnerable_topics)} SNS topics with policies that could "
                "be vulnerable to confused deputy attacks."
            ),
        )
