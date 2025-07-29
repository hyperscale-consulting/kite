import json

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization


class ScpPreventsLeavingOrgCheck:
    def __init__(self):
        self.check_id = "scp-prevents-leaving-org"
        self.check_name = "SCP Prevents Leaving Organization"

    @property
    def question(self) -> str:
        return ""  # fully automatic check

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is an SCP that denies the "
            "organizations:LeaveOrganization action and is attached to either "
            "the root OU or all top-level OUs."
        )

    def _is_leave_deny_scp(self, content: dict) -> bool:
        """
        Check if an SCP effectively denies the organizations:LeaveOrganization action.

        Args:
            content: The SCP content as a dictionary

        Returns:
            True if the SCP denies the organizations:LeaveOrganization action
        """
        if not isinstance(content, dict) or "Statement" not in content:
            return False

        statements = content["Statement"]
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if not isinstance(statement, dict):
                continue

            # Check for a deny statement with organizations:LeaveOrganization action
            if (
                statement.get("Effect") == "Deny"
                and "Action" in statement
                and statement["Action"] == "organizations:LeaveOrganization"
                and statement.get("Resource") == "*"
            ):
                return True

        return False

    def run(self) -> CheckResult:
        """
        Check if there is an effective SCP that prevents leaving the organization.

        This check verifies that:
        1. There is an SCP that denies the organizations:LeaveOrganization action
        2. The SCP is attached to either the root OU or all top-level OUs
        """
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "AWS Organizations is not being used, so SCP preventing "
                    "leaving organization cannot be assessed."
                ),
            )

        # Check root OU for leave organization deny SCP
        root_scps = org.root.scps
        root_has_leave_deny = False
        root_leave_deny_scp = None

        for scp in root_scps:
            try:
                content = json.loads(scp.content)
                if self._is_leave_deny_scp(content):
                    root_has_leave_deny = True
                    root_leave_deny_scp = scp
                    break
            except json.JSONDecodeError:
                continue

        # If root has leave deny SCP, we're good
        if root_has_leave_deny and root_leave_deny_scp:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "SCP preventing leaving organization is attached to the root OU."
                ),
            )

        # Check top-level OUs for leave deny SCP
        top_level_ous = org.root.child_ous
        ous_without_leave_deny = []

        # If there's no leave deny SCP on root and no top-level OUs, that's a fail
        if not top_level_ous:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "SCP preventing leaving organization is not attached to the "
                    "root OU and there are no top-level OUs."
                ),
            )

        for ou in top_level_ous:
            ou_has_leave_deny = False
            for scp in ou.scps:
                try:
                    content = json.loads(scp.content)
                    if self._is_leave_deny_scp(content):
                        ou_has_leave_deny = True
                        break
                except json.JSONDecodeError:
                    continue

            if not ou_has_leave_deny:
                ous_without_leave_deny.append(ou.name)

        if ous_without_leave_deny:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "SCP preventing leaving organization is not attached to the "
                    "root OU or all top-level OUs. The following top-level OUs "
                    "do not have a leave deny SCP: "
                )
                + ", ".join(ous_without_leave_deny),
            )

        return CheckResult(
            status=CheckStatus.PASS,
            reason=(
                "SCP preventing leaving organization is attached to all top-level OUs."
            ),
        )
