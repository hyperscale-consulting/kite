import json
from collections.abc import Callable

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.conditions import has_any_account_root_principal_condition
from hyperscale.kite.conditions import has_not_requested_region_condition
from hyperscale.kite.models import ControlPolicy
from hyperscale.kite.models import Organization


def _has_matching_stmt(
    scp: ControlPolicy, stmt_matcher: Callable[[str, list, dict], bool]
) -> bool:
    try:
        content = json.loads(scp.content)
    except json.JSONDecodeError:
        return False

    statements = content.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        effect = statement.get("Effect")
        actions = statement.get("Action", [])
        if not isinstance(actions, list):
            actions = [actions]
        conditions = statement.get("Condition", {})

        if stmt_matcher(effect, actions, conditions):
            return True
    return False


def _make_region_deny_stmt_matcher(
    active_regions: list,
) -> Callable[[str, list, dict], bool]:
    def _inner(effect: str, actions: list, conditions: dict) -> bool:
        if effect != "Deny":
            return False

        if "*" not in actions:
            return False

        return has_not_requested_region_condition(conditions, active_regions)

    return _inner


def _make_root_actions_disallowed_stmt_matcher(
    disallowed_actions: list,
) -> Callable[[str, list, dict], bool]:
    def _inner(effect: str, actions: list, conditions: dict) -> bool:
        if effect != "Deny":
            return False

        if not any(action in disallowed_actions for action in actions):
            return False

        return has_any_account_root_principal_condition(conditions)

    return _inner


def check_for_org_wide_region_deny_scp(
    organization: Organization | None, active_regions: list[str]
):
    return _check_for_org_wide_scp(
        organization, _make_region_deny_stmt_matcher(active_regions), "Region deny"
    )


def check_for_org_wide_disallow_root_actions_scp(organization: Organization | None):
    return _check_for_org_wide_scp(
        organization,
        _make_root_actions_disallowed_stmt_matcher(["*"]),
        "Disallow root actions",
    )


def check_for_org_wide_disallow_root_create_access_key_scp(
    organization: Organization | None,
):
    return _check_for_org_wide_scp(
        organization,
        _make_root_actions_disallowed_stmt_matcher(
            ["iam:CreateAccessKey", "*", "iam:Create*", "iam:*"]
        ),
        "Disallow root access keys creation",
    )


def _root_has_matching_scp(
    organization: Organization, matcher: Callable[[str, list, dict], bool]
) -> bool:
    return any(_has_matching_stmt(scp, matcher) for scp in organization.root.scps)


def _all_top_level_ous_have_matching_scp(
    org: Organization, matcher: Callable[[str, list, dict], bool]
) -> bool:
    if not org.root.child_ous:
        return False

    for ou in org.root.child_ous:
        if not any(_has_matching_stmt(scp, matcher) for scp in ou.scps):
            return False
    return True


def _check_for_org_wide_scp(
    organization: Organization | None,
    matcher: Callable[[str, list, dict], bool],
    scp_name,
) -> CheckResult:
    if organization is None:
        return CheckResult(
            status=CheckStatus.FAIL,
            reason="AWS Organizations is not being used, or the management account is "
            "not configured.",
        )

    if _root_has_matching_scp(organization, matcher):
        return CheckResult(
            status=CheckStatus.PASS,
            reason=f"{scp_name} SCP is attached to the root OU.",
        )

    if _all_top_level_ous_have_matching_scp(organization, matcher):
        return CheckResult(
            status=CheckStatus.PASS,
            reason=f"{scp_name} SCP is attached to all top-level OUs.",
        )

    return CheckResult(
        status=CheckStatus.FAIL,
        reason=(f"{scp_name} SCP is not attached to the root OU or all top-level OUs."),
    )
