"""Check if AWS Private Link is used for VPC routing instead of VPC peering."""

from typing import Dict, Any, Tuple

from kite.data import get_vpc_peering_connections
from kite.helpers import get_account_ids_in_scope, manual_check
from kite.config import Config


CHECK_ID = "use-private-link-for-vpc-routing"
CHECK_NAME = "Use Private Link for VPC Routing"


def _analyze_vpc_peering_connections() -> str:
    """Analyze VPC peering connections across all accounts and regions."""
    analysis = ""
    accounts = get_account_ids_in_scope()
    regions = Config.get().active_regions

    total_peering_connections = 0

    for account_id in accounts:
        account_has_connections = False
        account_analysis = f"\nAccount: {account_id}\n"

        for region in regions:
            peering_connections = get_vpc_peering_connections(account_id, region)

            if peering_connections:
                account_has_connections = True
                total_peering_connections += len(peering_connections)
                account_analysis += f"  Region: {region}\n"

                for connection in peering_connections:
                    connection_id = connection.get("VpcPeeringConnectionId", "Unknown")
                    status = connection.get("Status", {}).get("Code", "Unknown")
                    requester_vpc = (
                        connection.get("RequesterVpcInfo", {}).get("VpcId", "Unknown")
                    )
                    accepter_vpc = (
                        connection.get("AccepterVpcInfo", {}).get("VpcId", "Unknown")
                    )
                    requester_owner = (
                        connection.get("RequesterVpcInfo", {}).get("OwnerId", "Unknown")
                    )
                    accepter_owner = (
                        connection.get("AccepterVpcInfo", {}).get("OwnerId", "Unknown")
                    )

                    account_analysis += f"    VPC Peering Connection: {connection_id}\n"
                    account_analysis += f"      Status: {status}\n"
                    account_analysis += (
                        f"      Requester VPC: {requester_vpc} "
                        f"(Account: {requester_owner})\n"
                    )
                    account_analysis += (
                        f"      Accepter VPC: {accepter_vpc} "
                        f"(Account: {accepter_owner})\n"
                    )

                    # Add tags if present
                    tags = connection.get("Tags", [])
                    if tags:
                        tag_names = [
                            tag.get("Key", "") for tag in tags if tag.get("Key")
                        ]
                        if tag_names:
                            account_analysis += f"      Tags: {', '.join(tag_names)}\n"
                    account_analysis += "\n"

        if account_has_connections:
            analysis += account_analysis

    if total_peering_connections == 0:
        analysis = "\nNo VPC peering connections found in any account or region.\n"

    return analysis


def _pre_check() -> Tuple[bool, Dict[str, Any]]:
    """Pre-check function that automatically passes if no VPC peering connections exist."""
    peering_analysis = _analyze_vpc_peering_connections()

    if "No VPC peering connections found" in peering_analysis:
        msg_parts = [
            "No VPC peering connections found.",
            "This check passes automatically as there are no VPC peering",
            "connections to evaluate."
        ]
        msg = " ".join(msg_parts)
        result = {}
        result["check_id"] = CHECK_ID
        result["check_name"] = CHECK_NAME
        result["status"] = "PASS"
        details = {}
        details["message"] = msg
        result["details"] = details
        return False, result

    return True, {}


def check_use_private_link_for_vpc_routing() -> Dict[str, Any]:
    """Check if AWS Private Link is used for VPC routing instead of VPC peering."""
    peering_analysis = _analyze_vpc_peering_connections()

    message = (
        "This check helps you confirm whether you use AWS Private Link for simple "
        "routing between VPCs, rather than VPC peering connections.\n\n"
        "AWS Private Link provides private connectivity between VPCs, AWS services, "
        "and on-premises applications without exposing traffic to the internet. "
        "It can be a more secure and manageable alternative to VPC peering for "
        "certain use cases.\n\n"
        "Below is a summary of VPC peering connections found in your accounts:"
        "\n"
    )
    message += f"{peering_analysis}"

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Do you use AWS Private Link for simple routing between VPCs instead of "
            "VPC peering connections?"
        ),
        pass_message=(
            "AWS Private Link is used for VPC routing instead of VPC peering "
            "connections."
        ),
        fail_message=(
            "AWS Private Link should be used for VPC routing instead of VPC peering "
            "connections where appropriate."
        ),
        default=True,
        pre_check=_pre_check,
    )


check_use_private_link_for_vpc_routing._CHECK_ID = CHECK_ID
check_use_private_link_for_vpc_routing._CHECK_NAME = CHECK_NAME
