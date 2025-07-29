import json

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization


class ScpPreventsRamInvitationsCheck:
    def __init__(self):
        self.check_id = "scp-prevents-ram-invitations"
        self.check_name = "SCP Prevents RAM Resource Share Invitations"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is an SCP that prevents accepting "
            "RAM resource share invitations."
        )

    def run(self) -> CheckResult:
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "AWS Organizations is not being used, so SCP preventing "
                    "RAM invitations cannot be assessed."
                ),
            )

        # Check root OU for RAM invitation deny SCP
        root_scps = org.root.scps
        root_has_ram_deny = False
        root_ram_deny_scp = None

        for scp in root_scps:
            try:
                content = json.loads(scp.content)
                if self._is_ram_invitation_deny_scp(content):
                    root_has_ram_deny = True
                    root_ram_deny_scp = scp
                    break
            except json.JSONDecodeError:
                continue

        # If root has RAM invitation deny SCP, we're good
        if root_has_ram_deny and root_ram_deny_scp is not None:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "SCP preventing RAM resource share invitations is attached "
                    "to the root OU."
                ),
                details={
                    "scp": {
                        "id": root_ram_deny_scp.id,
                        "name": root_ram_deny_scp.name,
                        "arn": root_ram_deny_scp.arn,
                    },
                },
            )

        # Check top-level OUs for RAM invitation deny SCP
        top_level_ous = org.root.child_ous
        ous_without_ram_deny = []
        ous_with_ram_deny = []

        # If there's no RAM invitation deny SCP on root and no top-level OUs,
        # that's a fail
        if not top_level_ous:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "SCP preventing RAM resource share invitations is not "
                    "attached to the root OU and there are no top-level OUs."
                ),
            )

        for ou in top_level_ous:
            ou_has_ram_deny = False
            for scp in ou.scps:
                try:
                    content = json.loads(scp.content)
                    if self._is_ram_invitation_deny_scp(content):
                        ou_has_ram_deny = True
                        ous_with_ram_deny.append(
                            {
                                "ou_name": ou.name,
                                "scp": {
                                    "id": scp.id,
                                    "name": scp.name,
                                    "arn": scp.arn,
                                },
                            }
                        )
                        break
                except json.JSONDecodeError:
                    continue

            if not ou_has_ram_deny:
                ous_without_ram_deny.append(ou.name)

        if ous_without_ram_deny:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "SCP preventing RAM resource share invitations is not "
                    "attached to the root OU or all top-level OUs. The "
                    "following top-level OUs do not have a RAM invitation deny "
                    "SCP: "
                )
                + ", ".join(ous_without_ram_deny),
            )

        return CheckResult(
            status=CheckStatus.PASS,
            reason=(
                "SCP preventing RAM resource share invitations is attached to "
                "all top-level OUs."
            ),
            details={
                "scps_by_ou": ous_with_ram_deny,
            },
        )

    def _is_ram_invitation_deny_scp(self, content: dict) -> bool:
        if not isinstance(content, dict) or "Statement" not in content:
            return False

        statements = content["Statement"]
        if not isinstance(statements, list):
            statements = [statements]

        required_action = "ram:AcceptResourceShareInvitation"

        for statement in statements:
            if not isinstance(statement, dict):
                continue

            # Check for a deny statement with the required RAM action
            if (
                statement.get("Effect") == "Deny"
                and "Action" in statement
                and "Resource" in statement
                and statement["Resource"] == "*"
            ):
                actions = statement["Action"]
                if not isinstance(actions, list):
                    actions = [actions]

                # Check if the required action is present
                if required_action in actions:
                    return True

        return False
