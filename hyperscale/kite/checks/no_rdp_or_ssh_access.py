from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class NoRdpOrSshAccessCheck:
    def __init__(self):
        self.check_id = "no-rdp-or-ssh-access"
        self.check_name = "No RDP or SSH Access Exposed to Internet"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that RDP and SSH ports are not exposed to the "
            "internet."
        )

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        check_ids = [
            "ec2_instance_port_rdp_exposed_to_internet",
            "ec2_instance_port_ssh_exposed_to_internet",
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
                                "status": result.status,
                                "check_id": check_id,
                            }
                        )
        passed = len(failing_resources) == 0
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=(
                "No RDP or SSH ports are exposed to the internet."
                if passed
                else (
                    f"Found {len(failing_resources)} EC2 instances with RDP or SSH "
                    "ports exposed to the internet."
                )
            ),
            details={
                "failing_resources": failing_resources,
            },
        )
