import json

from kite.checks.core import CheckResult
from kite.checks.core import CheckStatus
from kite.data import get_organization
from kite.models import ControlPolicy
from kite.models import Organization


def _is_root_actions_disallow_scp(scp: ControlPolicy) -> bool:
    try:
        content = json.loads(scp.content)
    except json.JSONDecodeError:
        return False

    if not isinstance(content, dict) or "Statement" not in content:
        return False

    statements = content["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        # Check for a deny statement with "*" action
        if statement.get("Effect") == "Deny" and "Action" in statement:
            actions = statement["Action"]
            if not isinstance(actions, list):
                actions = [actions]

            # Check if the statement denies all actions
            if "*" in actions:
                # Must have a condition for root user
                if "Condition" not in statement:
                    continue

                condition = statement["Condition"]

                # Check for ArnLike condition
                if (
                    "ArnLike" in condition
                    and "aws:PrincipalArn" in condition["ArnLike"]
                ):
                    principal_arns = condition["ArnLike"]["aws:PrincipalArn"]
                    if not isinstance(principal_arns, list):
                        principal_arns = [principal_arns]

                    # Check if any of the ARNs match the root user pattern
                    if any(arn == "arn:*:iam::*:root" for arn in principal_arns):
                        return True

                # Check for StringLike condition
                if (
                    "StringLike" in condition
                    and "aws:PrincipalArn" in condition["StringLike"]
                ):
                    principal_arns = condition["StringLike"]["aws:PrincipalArn"]
                    if not isinstance(principal_arns, list):
                        principal_arns = [principal_arns]

                    # Check if any of the ARNs match the root user pattern
                    if any(arn == "arn:*:iam::*:root" for arn in principal_arns):
                        return True

    return False


def _root_scp_disallows_root_actions(org: Organization) -> bool:
    return _contains_root_actions_disallow_scp(org.root.scps)


def _contains_root_actions_disallow_scp(scps: list[ControlPolicy]) -> bool:
    for scp in scps:
        if _is_root_actions_disallow_scp(scp):
            return True
    return False


def _all_top_level_ous_have_root_actions_disallow_scp(org: Organization) -> bool:
    if not org.root.child_ous:
        return False

    for ou in org.root.child_ous:
        if not _contains_root_actions_disallow_scp(ou.scps):
            return False
    return True


class RootActionsDisallowedCheck:
    def __init__(self):
        self.check_id = "root-actions-disallowed"
        self.check_name = "Root Actions Disallowed"

    @property
    def question(self) -> str:
        return "Does the root OU have a disallow root actions SCP?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that SCPs are applies that prevent root user "
            "actions across the whole organization."
        )

    def run(self) -> CheckResult:
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="AWS Organizations is not being used, so SCPs cannot be used.",
            )

        if _root_scp_disallows_root_actions(org):
            return CheckResult(
                status=CheckStatus.PASS,
                reason="Disallow root actions SCP is attached to the root OU.",
            )

        if _all_top_level_ous_have_root_actions_disallow_scp(org):
            return CheckResult(
                status=CheckStatus.PASS,
                reason="Disallow root actions SCP is attached to all top-level OUs.",
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                "Root actions disallow SCP is not attached to the root OU or all "
                "top-level OUs."
            ),
        )
