from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class NoPolicyAllowsPrivilegeEscalationCheck:
    def __init__(self):
        self.check_id = "no-policy-allows-privilege-escalation"
        self.check_name = "No IAM Policy Allows Privilege Escalation"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that IAM policies (both inline and managed) do not "
            "allow privilege escalation."
        )

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        check_ids = [
            "iam_inline_policy_allows_privilege_escalation",
            "iam_policy_allows_privilege_escalation",
        ]
        failing_resources = []
        for check_id in check_ids:
            if check_id in prowler_results:
                results = prowler_results[check_id]
                for result in results:
                    if result.status != "PASS":
                        failing_resources.append(
                            {
                                "account_id": result.account_id,
                                "resource_uid": result.resource_uid,
                                "resource_name": result.resource_name,
                                "resource_details": result.resource_details,
                                "region": result.region,
                                "check_id": check_id,
                                "status": result.status,
                            }
                        )
        passed = len(failing_resources) == 0
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=(
                "No IAM policies were found that allow privilege escalation."
                if passed
                else (
                    f"Found {len(failing_resources)} IAM policies that allow "
                    "privilege escalation."
                )
            ),
            details={
                "failing_resources": failing_resources,
            },
        )
