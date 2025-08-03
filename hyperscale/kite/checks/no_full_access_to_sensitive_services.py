from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class NoFullAccessToSensitiveServicesCheck:
    def __init__(self):
        self.check_id = "no-full-access-to-sensitive-services"
        self.check_name = "No Full Access to Sensitive Services"

    @property
    def question(self) -> str:
        return ""

    @property
    def description(self) -> str:
        return (
            "This check verifies that IAM policies (both inline and managed) do not "
            "allow full access to sensitive services."
        )

    def run(self) -> CheckResult:
        # Get Prowler results
        prowler_results = get_prowler_output()

        # The check IDs we're interested in
        check_ids = [
            "iam_policy_no_full_access_to_cloudtrail",
            "iam_inline_policy_no_full_access_to_cloudtrail",
            "iam_policy_no_full_access_to_kms",
            "iam_inline_policy_no_full_access_to_kms",
            "iam_policy_cloudshell_admin_not_attached",
        ]

        # Track failing resources
        failing_resources: list[dict] = []

        # Check results for each check ID
        for check_id in check_ids:
            if check_id in prowler_results:
                # Get results for this check ID
                results = prowler_results[check_id]

                # Add failing resources to the list
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

        # Determine if the check passed
        passed = len(failing_resources) == 0

        if passed:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "No IAM policies were found that allow full access to sensitive "
                    "services."
                ),
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                f"Found {len(failing_resources)} IAM policies that allow full "
                "access to sensitive services."
            ),
            details={"failing_resources": failing_resources},
        )
