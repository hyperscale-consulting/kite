from collections import defaultdict

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_inspector2_configuration
from hyperscale.kite.data import get_inspector2_coverage
from hyperscale.kite.helpers import get_account_ids_in_scope


class ScanWorkloadsForVulnerabilitiesCheck:
    def __init__(self):
        self.check_id = "scan-workloads-for-vulnerabilities"
        self.check_name = "Scan Workloads for Vulnerabilities"

    @property
    def question(self) -> str:
        return (
            "Are workloads continuously scanned for software vulnerabilities, "
            "potential defects, and unintended network exposure?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that workloads are continuously scanned for "
            "software vulnerabilities, potential defects, and unintended network "
            "exposure."
        )

    def run(self) -> CheckResult:
        summary = self._inspector_usage_summary()
        message = "AWS Inspector Usage Details:\n\n"
        if summary["accounts_missing_scanning"]:
            message += "Accounts missing EC2/ECR scanning in some regions:\n"
            for account, regions in summary["accounts_missing_scanning"].items():
                message += f"- Account {account}: {', '.join(regions)}\n"
        else:
            message += (
                "All accounts have EC2 and ECR scanning enabled in all regions.\n"
            )
        message += "\nResource types scanned by Inspector across all accounts:\n"
        if summary["scanned_resource_types"]:
            for rtype in summary["scanned_resource_types"]:
                message += f"- {rtype}\n"
        else:
            message += "No resources are currently scanned by Inspector.\n"

        message += (
            "\nPlease review the above and confirm that workloads are continuously "
            "scanned for software vulnerabilities, potential defects, and "
            "unintended network exposure."
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )

    def _inspector_usage_summary(self) -> dict:
        accounts_missing_scanning = defaultdict(list)
        scanned_resource_types: set[str] = set()
        config = Config.get()
        account_ids = get_account_ids_in_scope()

        for account_id in account_ids:
            for region in config.active_regions:
                conf = get_inspector2_configuration(account_id, region)
                ec2_ok = (
                    conf.get("ec2Configuration", {})
                    .get("scanModeState", {})
                    .get("scanModeStatus")
                    == "SUCCESS"
                )
                ecr_ok = (
                    conf.get("ecrConfiguration", {})
                    .get("rescanDurationState", {})
                    .get("status")
                    == "SUCCESS"
                )
                if not (ec2_ok and ecr_ok):
                    accounts_missing_scanning[account_id].append(region)

                coverage = get_inspector2_coverage(account_id, region)
                for resource in coverage:
                    rtype = resource.get("resourceType")
                    if rtype:
                        scanned_resource_types.add(rtype)

        return {
            "accounts_missing_scanning": dict(accounts_missing_scanning),
            "scanned_resource_types": sorted(list(scanned_resource_types)),
        }
