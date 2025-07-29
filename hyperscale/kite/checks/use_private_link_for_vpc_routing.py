from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_vpc_peering_connections
from hyperscale.kite.helpers import get_account_ids_in_scope


class UsePrivateLinkForVpcRoutingCheck:
    def __init__(self):
        self.check_id = "use-private-link-for-vpc-routing"
        self.check_name = "Use Private Link for VPC Routing"

    @property
    def question(self) -> str:
        return (
            "Do you use AWS Private Link for simple routing between VPCs instead of "
            "VPC peering connections?"
        )

    @property
    def description(self) -> str:
        return (
            "This check helps verify that AWS Private Link is used for simple "
            "routing between VPCs, rather than VPC peering connections."
        )

    def run(self) -> CheckResult:
        peering_analysis = _analyze_vpc_peering_connections()

        # If no VPC peering connections found, automatically pass
        if "No VPC peering connections found" in peering_analysis:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "No VPC peering connections found. This check passes automatically "
                    "as there are no VPC peering connections to evaluate."
                ),
            )

        # For VPC peering connections, require manual review
        message = (
            "AWS Private Link provides private connectivity between VPCs. It can be a "
            "more secure alternative to VPC peering when your workload only requires "
            "traffic flows between specific components in different VPCs.\n\n"
            "Below is a summary of VPC peering connections found in your accounts:"
            "\n"
        )
        message += f"{peering_analysis}"

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )


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
                    requester_vpc = connection.get("RequesterVpcInfo", {}).get(
                        "VpcId", "Unknown"
                    )
                    accepter_vpc = connection.get("AccepterVpcInfo", {}).get(
                        "VpcId", "Unknown"
                    )
                    requester_owner = connection.get("RequesterVpcInfo", {}).get(
                        "OwnerId", "Unknown"
                    )
                    accepter_owner = connection.get("AccepterVpcInfo", {}).get(
                        "OwnerId", "Unknown"
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
