"""Check for Network Firewall configuration and coverage."""

from typing import Any

from kite.config import Config
from kite.data import get_networkfirewall_firewalls
from kite.data import get_vpcs
from kite.helpers import get_account_ids_in_scope
from kite.helpers import manual_check

CHECK_ID = "inspect-traffic-with-network-firewall"
CHECK_NAME = "Inspect Traffic with Network Firewall"


def _pre_check() -> tuple[bool, dict[str, Any]]:
    """Pre-check function that automatically fails if no network firewalls exist."""
    accounts = get_account_ids_in_scope()
    regions = Config.get().active_regions

    total_firewalls = 0
    for account_id in accounts:
        for region in regions:
            firewalls = get_networkfirewall_firewalls(account_id, region)
            total_firewalls += len(firewalls)

    if total_firewalls == 0:
        msg = "No Network Firewalls found across all accounts and regions."
        result = {}
        result["check_id"] = CHECK_ID
        result["check_name"] = CHECK_NAME
        result["status"] = "FAIL"
        details = {}
        details["message"] = msg
        result["details"] = details
        return False, result

    return True, {}


def _get_vpc_name(vpc: dict[str, Any]) -> str:
    tags = vpc.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", "Unknown")
    return "Unknown"


def _analyze_network_firewalls() -> str:
    """Analyze Network Firewall configurations and coverage.

    Returns:
        Analysis string with firewall details and warnings.
    """
    accounts = get_account_ids_in_scope()
    regions = Config.get().active_regions

    analysis_lines = []
    analysis_lines.append("Network Firewall Configuration Analysis")
    analysis_lines.append("=" * 50)
    analysis_lines.append("")

    # Track VPCs with firewalls
    vpcs_with_firewalls = set()
    total_firewalls = 0

    for account_id in accounts:
        account_has_firewalls = False
        account_has_resources = False

        for region in regions:
            firewalls = get_networkfirewall_firewalls(account_id, region)
            vpcs = get_vpcs(account_id, region)

            if firewalls:
                account_has_firewalls = True
                total_firewalls += len(firewalls)

                analysis_lines.append(f"Account {account_id} - Region {region}:")
                analysis_lines.append("-" * 60)

                for firewall in firewalls:
                    analysis_lines.append(
                        f"  Firewall: {firewall.get('FirewallName', 'N/A')}"
                    )
                    analysis_lines.append(f"  VPC ID: {firewall.get('VpcId', 'N/A')}")
                    analysis_lines.append(
                        f"  Description: {firewall.get('Description', 'N/A')}"
                    )
                    status = firewall.get("FirewallStatus", {})
                    analysis_lines.append(f"  Status: {status.get('Status', 'N/A')}")
                    analysis_lines.append("")

                    # Track VPC with firewall
                    vpc_id = firewall.get("VpcId")
                    if vpc_id:
                        vpc_key = f"{account_id}:{region}:{vpc_id}"
                        vpcs_with_firewalls.add(vpc_key)

            if vpcs:
                account_has_resources = True

        # Only show account if it has firewalls or resources
        if account_has_firewalls or account_has_resources:
            if not account_has_firewalls:
                analysis_lines.append(
                    f"Account {account_id}: No Network Firewalls configured"
                )
                analysis_lines.append("")

    # Check for VPCs without firewalls
    analysis_lines.append("VPCs Without Network Firewalls:")
    analysis_lines.append("=" * 40)
    analysis_lines.append("")

    vpcs_without_firewalls = []
    for account_id in accounts:
        for region in regions:
            vpcs = get_vpcs(account_id, region)
            for vpc in vpcs:
                vpc_id = vpc.get("VpcId")
                if vpc_id:
                    vpc_key = f"{account_id}:{region}:{vpc_id}"
                    if vpc_key not in vpcs_with_firewalls:
                        vpcs_without_firewalls.append(
                            {
                                "account_id": account_id,
                                "region": region,
                                "vpc_id": vpc_id,
                                "vpc_name": _get_vpc_name(vpc),
                            }
                        )

    if vpcs_without_firewalls:
        for vpc_info in vpcs_without_firewalls:
            vpc_id = vpc_info["vpc_id"]
            vpc_name = vpc_info["vpc_name"]
            account_id = vpc_info["account_id"]
            region = vpc_info["region"]

            warning_msg = (
                f"  WARNING: VPC {vpc_id} ({vpc_name}) in account "
                f"{account_id} region {region} has no Network Firewall"
            )
            analysis_lines.append(warning_msg)
    else:
        analysis_lines.append("  All VPCs have Network Firewalls configured")

    analysis_lines.append("")
    analysis_lines.append(f"Summary: {total_firewalls} Network Firewalls found")
    analysis_lines.append(f"VPCs without firewalls: {len(vpcs_without_firewalls)}")

    return "\n".join(analysis_lines)


def check_inspect_traffic_with_network_firewall() -> dict[str, Any]:
    """Check Network Firewall configuration and coverage."""
    analysis = _analyze_network_firewalls()

    message = (
        "This check helps you confirm whether Network Firewall is properly configured "
        "to inspect traffic in your VPCs.\n\n"
        "AWS Network Firewall provides stateful inspection, intrusion prevention, "
        "and web filtering capabilities for your VPC traffic.\n\n"
        "Below is a summary of Network Firewall configurations and VPCs without "
        "firewalls:\n"
    )
    message += f"{analysis}"

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=("Do you use Network Firewall to inspect traffic in your VPCs?"),
        pass_message=("Network Firewall is used to inspect traffic in VPCs."),
        fail_message=(
            "Network Firewall should be used to inspect traffic in VPCs where "
            "appropriate."
        ),
        default=True,
        pre_check=_pre_check,
    )


check_inspect_traffic_with_network_firewall._CHECK_ID = CHECK_ID
check_inspect_traffic_with_network_firewall._CHECK_NAME = CHECK_NAME
