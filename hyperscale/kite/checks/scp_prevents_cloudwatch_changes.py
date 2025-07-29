import json

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization


class ScpPreventsCloudwatchChangesCheck:
    def __init__(self):
        self.check_id = "scp-prevents-cloudwatch-changes"
        self.check_name = "SCP Prevents CloudWatch Changes"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is an SCP that prevents changes to "
            "CloudWatch configuration."
        )

    def run(self) -> CheckResult:
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "AWS Organizations is not being used, so SCP preventing "
                    "CloudWatch changes cannot be assessed."
                ),
            )

        matching_scps = self._check_ous_recursively(org.root)

        if matching_scps:
            scps_by_ou = {}
            for ou_name, scp_details in matching_scps:
                if ou_name not in scps_by_ou:
                    scps_by_ou[ou_name] = []
                scps_by_ou[ou_name].append(scp_details)

            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "Found SCPs preventing CloudWatch changes in the following OUs: "
                )
                + ", ".join(scps_by_ou.keys()),
                details={
                    "scps_by_ou": scps_by_ou,
                },
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                "No SCP preventing CloudWatch changes was found in any OU in "
                "the organization."
            ),
        )

    def _check_ou_for_cloudwatch_deny(self, ou) -> list[tuple[str, dict[str, str]]]:
        matching_scps = []
        for scp in ou.scps:
            try:
                content = json.loads(scp.content)
                if self._is_cloudwatch_deny_scp(content):
                    matching_scps.append(
                        (
                            ou.name,
                            {
                                "id": scp.id,
                                "name": scp.name,
                                "arn": scp.arn,
                            },
                        )
                    )
            except json.JSONDecodeError:
                continue
        return matching_scps

    def _check_ous_recursively(self, ou) -> list[tuple[str, dict[str, str]]]:
        matching_scps = []

        matching_scps.extend(self._check_ou_for_cloudwatch_deny(ou))

        for child_ou in ou.child_ous:
            matching_scps.extend(self._check_ous_recursively(child_ou))

        return matching_scps

    def _is_cloudwatch_deny_scp(self, content: dict) -> bool:
        if not isinstance(content, dict) or "Statement" not in content:
            return False

        statements = content["Statement"]
        if not isinstance(statements, list):
            statements = [statements]

        required_actions = {
            "cloudwatch:DeleteAlarms",
            "cloudwatch:DeleteDashboards",
            "cloudwatch:DisableAlarmActions",
            "cloudwatch:PutDashboard",
            "cloudwatch:PutMetricAlarm",
            "cloudwatch:SetAlarmState",
        }

        for statement in statements:
            if not isinstance(statement, dict):
                continue

            if (
                statement.get("Effect") == "Deny"
                and "Action" in statement
                and "Resource" in statement
                and statement["Resource"] == "*"
            ):
                actions = statement["Action"]
                if not isinstance(actions, list):
                    actions = [actions]

                if all(action in actions for action in required_actions):
                    return True

        return False
