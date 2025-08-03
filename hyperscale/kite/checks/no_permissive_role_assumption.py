from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class NoPermissiveRoleAssumptionCheck:
    def __init__(self):
        self.check_id = "no-permissive-role-assumption"
        self.check_name = "No Permissive Role Assumption"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that IAM policies do not allow permissive role "
            "assumption."
        )

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        check_id = "iam_no_custom_policy_permissive_role_assumption"
        failing_resources = []
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
                            "status": result.status,
                        }
                    )
        passed = len(failing_resources) == 0
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=(
                "No IAM policies were found that allow permissive role assumption."
                if passed
                else (
                    f"Found {len(failing_resources)} IAM policies that allow "
                    "permissive role assumption."
                )
            ),
            details={
                "failing_resources": failing_resources,
            },
        )
