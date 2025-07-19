import json

from kite.checks.core import CheckResult
from kite.checks.core import CheckStatus
from kite.conditions import has_any_account_root_principal_condition
from kite.models import ControlPolicy
from kite.models import Organization


def _is_root_actions_disallow_scp(scp: ControlPolicy, actions: list[str]) -> bool:
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
            stmt_actions = statement["Action"]
            if not isinstance(stmt_actions, list):
                stmt_actions = [stmt_actions]

            # Check if the statement denies any of the provided actions
            for action in actions:
                if action in stmt_actions:
                    # Must have a condition for root user
                    if "Condition" not in statement:
                        continue

                    condition = statement["Condition"]
                    if has_any_account_root_principal_condition(condition):
                        return True

    return False


def _root_scp_disallows_root_action(org: Organization, actions: list[str]) -> bool:
    return _contains_root_action_disallow_scp(org.root.scps, actions)


def _contains_root_action_disallow_scp(
    scps: list[ControlPolicy], actions: list[str]
) -> bool:
    for scp in scps:
        if _is_root_actions_disallow_scp(scp, actions):
            return True
    return False


def _all_top_level_ous_have_root_action_disallow_scp(
    org: Organization, actions: list[str]
) -> bool:
    if not org.root.child_ous:
        return False

    for ou in org.root.child_ous:
        if not _contains_root_action_disallow_scp(ou.scps, actions):
            return False
    return True


def check_for_org_wide_disallow_root_actions_scp(organization: Organization | None):
    return _check_for_org_wide_disallow_root_action_scp(
        organization, ["*"], "Disallow root actions"
    )


def check_for_org_wide_disallow_root_create_access_key_scp(
    organization: Organization | None,
):
    return _check_for_org_wide_disallow_root_action_scp(
        organization,
        ["iam:CreateAccessKey", "*", "iam:Create*", "iam:*"],
        "Disallow root access keys creation",
    )


def _check_for_org_wide_disallow_root_action_scp(
    organization: Organization | None, actions: list[str], scp_name: str
) -> CheckResult:
    if organization is None:
        return CheckResult(
            status=CheckStatus.FAIL,
            reason="AWS Organizations is not being used, or the management account is "
            "not configured.",
        )

    if _root_scp_disallows_root_action(organization, actions):
        return CheckResult(
            status=CheckStatus.PASS,
            reason=f"{scp_name} SCP is attached to the root OU.",
        )

    if _all_top_level_ous_have_root_action_disallow_scp(organization, actions):
        return CheckResult(
            status=CheckStatus.PASS,
            reason=f"{scp_name} SCP is attached to all top-level OUs.",
        )

    return CheckResult(
        status=CheckStatus.FAIL,
        reason=(f"{scp_name} SCP is not attached to the root OU or all top-level OUs."),
    )
