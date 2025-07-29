from typing import Any

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.conditions import has_confused_deputy_protection
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_sqs_queues
from hyperscale.kite.helpers import get_account_ids_in_scope


class SqsConfusedDeputyProtectionCheck:
    def __init__(self):
        self.check_id = "sqs-confused-deputy-protection"
        self.check_name = "SQS Queue Confused Deputy Protection"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check identifies SQS queue policies that allow actions to be "
            "performed by service principals without proper confused deputy protection "
            "via conditions on aws:SourceAccount, aws:SourceArn, aws:SourceOrgID, or "
            "aws:SourceOrgPaths."
        )

    def run(self) -> CheckResult:
        vulnerable_queues = []
        config = Config.get()

        # Get all SQS queues
        for account_id in get_account_ids_in_scope():
            for region in config.active_regions:
                queues = get_sqs_queues(account_id, region)

                for queue in queues:
                    queue_arn = queue["QueueArn"]
                    policy = queue.get("Policy")

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
                        if any(_is_service_principal(p) for p in principals):
                            vulnerable_queues.append(
                                {
                                    "account_id": account_id,
                                    "region": region,
                                    "queue_arn": queue_arn,
                                    "statement": statement,
                                }
                            )

        if not vulnerable_queues:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="All SQS queue policies have proper confused deputy protection.",
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                f"Found {len(vulnerable_queues)} SQS queues with policies that could "
                "be vulnerable to confused deputy attacks."
            ),
        )


def _is_service_principal(principal: Any) -> bool:
    """
    Check if a principal is a service principal.

    Args:
        principal: The principal to check (can be string or list)

    Returns:
        True if the principal is a service principal, False otherwise
    """
    if isinstance(principal, list):
        return any(_is_service_principal(p) for p in principal)
    if not isinstance(principal, str):
        return False
    return principal.endswith(".amazonaws.com")
