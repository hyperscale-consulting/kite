import json

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization


class ScpPreventsDeletingLogsCheck:
    def __init__(self):
        self.check_id = "scp-prevents-deleting-logs"
        self.check_name = "SCP Prevents Deleting Logs"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return "This check verifies that there is an SCP that prevents deleting logs."

    def run(self) -> CheckResult:
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "AWS Organizations is not being used, so SCP preventing "
                    "log deletion cannot be assessed."
                ),
            )

        # Find all OUs with log deletion deny SCPs
        matching_scps = self._find_matching_scps(org.root)

        if not matching_scps:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "No SCP preventing log deletion was found in any OU in the "
                    "organization."
                ),
            )

        return CheckResult(
            status=CheckStatus.PASS,
            reason=(
                f"Found {len(matching_scps)} SCP(s) preventing log deletion "
                "across the organization."
            ),
            details={
                "scps_by_ou": matching_scps,
            },
        )

    def _find_matching_scps(self, ou) -> list[dict]:
        matching_scps = []

        # Check current OU's SCPs
        for scp in ou.scps:
            try:
                content = json.loads(scp.content)
                if self._is_log_deletion_deny_scp(content):
                    matching_scps.append(
                        {
                            "ou_name": ou.name,
                            "scp": {
                                "id": scp.id,
                                "name": scp.name,
                                "arn": scp.arn,
                            },
                        }
                    )
            except json.JSONDecodeError:
                continue

        # Recursively check child OUs
        for child_ou in ou.child_ous:
            matching_scps.extend(self._find_matching_scps(child_ou))

        return matching_scps

    def _is_log_deletion_deny_scp(self, content: dict) -> bool:
        if not isinstance(content, dict) or "Statement" not in content:
            return False

        statements = content["Statement"]
        if not isinstance(statements, list):
            statements = [statements]

        required_actions = {
            "ec2:DeleteFlowLogs",
            "logs:DeleteLogGroup",
            "logs:DeleteLogStream",
        }

        for statement in statements:
            if not isinstance(statement, dict):
                continue

            # Check for a deny statement with the required log deletion actions
            if (
                statement.get("Effect") == "Deny"
                and "Action" in statement
                and "Resource" in statement
                and statement["Resource"] == "*"
            ):
                actions = statement["Action"]
                if not isinstance(actions, list):
                    actions = [actions]

                # Check if all required actions are present
                if all(action in actions for action in required_actions):
                    return True

        return False
