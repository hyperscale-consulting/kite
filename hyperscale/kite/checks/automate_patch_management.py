from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_ec2_instances
from hyperscale.kite.data import get_maintenance_windows
from hyperscale.kite.helpers import get_account_ids_in_scope
from hyperscale.kite.prowler import get_prowler_output


class AutomatePatchManagementCheck:
    def __init__(self):
        self.check_id = "automate-patch-management"
        self.check_name = "Automate Patch Management"

    @property
    def question(self) -> str:
        return (
            "Is automatic patch management implemented for EC2 instances using "
            "AWS Systems Manager Maintenance Windows and SSM managed patching?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that automatic patch management is implemented for "
            "EC2 instances using AWS Systems Manager Maintenance Windows and SSM "
            "managed patching."
        )

    def _format_maintenance_window_details(self, maintenance_windows):
        if not maintenance_windows:
            return "  No maintenance windows found.\n"
        details = ""
        for mw in maintenance_windows:
            if not mw.get("Enabled", False):
                continue
            details += f"  Maintenance Window: {mw.get('Name', 'Unknown')}\n"
            details += f"    Window ID: {mw.get('WindowId', 'Unknown')}\n"
            details += f"    Schedule: {mw.get('Schedule', 'Unknown')}\n"
            details += f"    Duration: {mw.get('Duration', 'Unknown')} hours\n"
            details += f"    Cutoff: {mw.get('Cutoff', 'Unknown')} hours\n"
            targets = mw.get("Targets", [])
            if targets:
                details += f"    Targets ({len(targets)}):\n"
                for target in targets:
                    details += f"      - Name: {target.get('Name', 'Unknown')}\n"
                    details += f"        Targets: {target.get('Targets', [])}\n"
            else:
                details += "    Targets: None\n"
            tasks = mw.get("Tasks", [])
            if tasks:
                details += f"    Tasks ({len(tasks)}):\n"
                for task in tasks:
                    details += f"      - Name: {task.get('Name', 'Unknown')}\n"
                    details += f"        Type: {task.get('Type', 'Unknown')}\n"
                    details += f"        Task ARN: {task.get('TaskArn', 'Unknown')}\n"
            else:
                details += "    Tasks: None\n"
            details += "\n"
        return details

    def _format_prowler_results(self, accounts_with_ec2):
        prowler_results = get_prowler_output()
        check_id = "ssm_managed_compliant_patching"
        if check_id not in prowler_results:
            return "  No SSM managed compliant patching prowler results found.\n"
        results = prowler_results[check_id]
        relevant_results = []
        for result in results:
            account_id = result.account_id
            region = result.region
            if (
                account_id in accounts_with_ec2
                and region in accounts_with_ec2[account_id]
            ):
                relevant_results.append(result)
        if not relevant_results:
            return (
                "  No SSM managed compliant patching results found for "
                "accounts with EC2 instances.\n"
            )
        details = "  SSM Managed Compliant Patching Results:\n"
        by_account = {}
        for result in relevant_results:
            account_id = result.account_id
            region = result.region
            if account_id not in by_account:
                by_account[account_id] = {}
            if region not in by_account[account_id]:
                by_account[account_id][region] = []
            by_account[account_id][region].append(result)
        for account_id, regions in by_account.items():
            details += f"    Account: {account_id}\n"
            for region, region_results in regions.items():
                details += f"      Region: {region}\n"
                pass_count = sum(1 for r in region_results if r.status == "PASS")
                fail_count = sum(1 for r in region_results if r.status == "FAIL")
                error_count = sum(1 for r in region_results if r.status == "ERROR")
                details += (
                    f"        Status: PASS={pass_count}, "
                    f"FAIL={fail_count}, ERROR={error_count}\n"
                )
                failing_resources = [r for r in region_results if r.status != "PASS"]
                if failing_resources:
                    details += (
                        f"        Failing Resources ({len(failing_resources)}):\n"
                    )
                    for resource in failing_resources:
                        resource_name = resource.resource_name or resource.resource_uid
                        details += f"          - {resource_name}\n"
                        details += f"            Details: {resource.resource_details}\n"
                else:
                    details += (
                        "        All resources compliant with SSM managed patching.\n"
                    )
        return details

    def run(self) -> CheckResult:
        account_ids = get_account_ids_in_scope()
        if not account_ids:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="No accounts in scope found.",
                details={},
            )
        accounts_with_ec2 = {}
        has_ec2_instances = False
        config = Config.get()
        for account_id in account_ids:
            regions_with_ec2 = {}
            for region in config.active_regions:
                instances = get_ec2_instances(account_id, region)
                if instances:
                    has_ec2_instances = True
                    regions_with_ec2[region] = instances
            if regions_with_ec2:
                accounts_with_ec2[account_id] = regions_with_ec2
        message = "Automated Patch Management Check:\n\n"
        if not has_ec2_instances:
            message += (
                "No EC2 instances found in any account. This check is not applicable.\n"
            )
            return CheckResult(
                status=CheckStatus.PASS,
                reason=message,
                details={"accounts_with_ec2": accounts_with_ec2},
            )
        message += "EC2 instances found in the following accounts and regions:\n\n"
        for account_id, regions in accounts_with_ec2.items():
            message += f"Account: {account_id}\n"
            for region, instances in regions.items():
                message += f"  Region: {region}\n"
                message += f"  EC2 Instances: {len(instances)}\n"
                maintenance_windows = get_maintenance_windows(account_id, region)
                message += "  Maintenance Windows:\n"
                message += self._format_maintenance_window_details(maintenance_windows)
            message += "\n"
        message += self._format_prowler_results(accounts_with_ec2)
        message += "\n"
        message += (
            "Please review the above maintenance window details and SSM patching "
            "results, then confirm that automatic patch management is implemented for "
            "EC2 instances\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
