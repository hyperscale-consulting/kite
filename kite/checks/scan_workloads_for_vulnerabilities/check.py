"""Check for continuous vulnerability scanning of workloads."""

from collections import defaultdict
from typing import Any

from kite.config import Config
from kite.data import get_inspector2_configuration
from kite.data import get_inspector2_coverage
from kite.helpers import get_account_ids_in_scope
from kite.helpers import manual_check

CHECK_ID = "scan-workloads-for-vulnerabilities"
CHECK_NAME = "Scan Workloads for Vulnerabilities"


def _inspector_usage_summary() -> dict[str, Any]:
    """
    Gather Inspector usage details.
    Returns a dict with:
      - accounts_missing_scanning: {account_id: [regions]} for accounts missing
        EC2/ECR scanning
      - scanned_resource_types: set of all resource types scanned by Inspector
    """
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

            # Inspector coverage
            coverage = get_inspector2_coverage(account_id, region)
            for resource in coverage:
                rtype = resource.get("resourceType")
                if rtype:
                    scanned_resource_types.add(rtype)

    return {
        "accounts_missing_scanning": dict(accounts_missing_scanning),
        "scanned_resource_types": sorted(list(scanned_resource_types)),
    }


def check_scan_workloads_for_vulnerabilities() -> dict[str, Any]:
    """
    Check if workloads are continuously scanned for software vulnerabilities,
    potential defects, and unintended network exposure.
    Presents Inspector usage details to the user.
    """
    summary = _inspector_usage_summary()
    message = "AWS Inspector Usage Details:\n\n"
    if summary["accounts_missing_scanning"]:
        message += "Accounts missing EC2/ECR scanning in some regions:\n"
        for account, regions in summary["accounts_missing_scanning"].items():
            message += f"- Account {account}: {', '.join(regions)}\n"
    else:
        message += "All accounts have EC2 and ECR scanning enabled in all regions.\n"
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

    prompt = (
        "Are workloads continuously scanned for software vulnerabilities, "
        "potential defects, and unintended network exposure?"
    )
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Workloads are continuously scanned for vulnerabilities, defects, "
            "and exposure."
        ),
        fail_message=(
            "Workloads should be continuously scanned for vulnerabilities, "
            "defects, and exposure."
        ),
        default=True,
    )


check_scan_workloads_for_vulnerabilities._CHECK_ID = CHECK_ID
check_scan_workloads_for_vulnerabilities._CHECK_NAME = CHECK_NAME
