from collections import defaultdict

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.utils import get_name_from_tag
from hyperscale.kite.checks.utils import get_vpcs_with_resources
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_rtbs
from hyperscale.kite.helpers import get_account_ids_in_scope


def _analyze() -> str:
    accounts = get_account_ids_in_scope()
    config = Config.get()
    analysis = "Route Table Network Flow Analysis:\n\n"
    vpcs_by_account_and_region = defaultdict(dict)
    for account_id in accounts:
        for region in config.active_regions:
            vpcs_with_resources = get_vpcs_with_resources(account_id, region)
            if vpcs_with_resources:
                vpcs_by_account_and_region[account_id][region] = vpcs_with_resources

    for account_id, regions in vpcs_by_account_and_region.items():
        analysis += account_id + "\n" + "=" * 50 + "\n\n"
        for region, vpcs in regions.items():
            route_tables = get_rtbs(account_id, region)
            analysis += f"Region: {region}\n" + "-" * 30 + "\n\n"
            for vpc in vpcs:
                analysis += f"VPC: {vpc['VpcId']} - CIDR: {vpc['CidrBlock']}\n"
                for subnet in vpc["Subnets"]:
                    analysis += _analyze_subnet(subnet, route_tables)

    return analysis


def _analyze_subnet(subnet, rtbs):
    subnet_id = subnet["SubnetId"]
    subnet_name = get_name_from_tag(subnet)
    subnet_cidr = subnet["CidrBlock"]
    az = subnet["AvailabilityZone"]
    analysis = (
        f"  Subnet: {subnet_id} (Name: {subnet_name}) - CIDR: {subnet_cidr} - AZ: {az}"
    )
    analysis += "\n"
    resources_by_type = subnet.get("Resources", {})
    for resource_type, resources in resources_by_type.items():
        analysis += f"    {resource_type}:"
        analysis += "\n"
        for resource in resources:
            resource_name = resource["Name"]
            analysis += f"      - {resource_name}\n"

        subnet_rtbs = _get_route_tables_for_subnet(subnet_id, rtbs)
        if subnet_rtbs:
            for rtb in subnet_rtbs:
                for line in _summarize_route_table(rtb):
                    analysis += f"      {line}\n"
        else:
            analysis += "    No route table associated with this subnet.\n"

    return analysis


def _summarize_route_table(rtb):
    summary = []
    rtb_id = rtb.get("RouteTableId", "Unknown")
    summary.append(f"Route Table: {rtb_id}")
    for route in rtb.get("Routes", []):
        destination = (
            route.get("DestinationCidrBlock")
            or route.get("DestinationIpv6CidrBlock")
            or route.get("DestinationPrefixListId")
            or "?"
        )
        target = (
            route.get("GatewayId")
            or route.get("NatGatewayId")
            or route.get("TransitGatewayId")
            or route.get("VpcPeeringConnectionId")
            or route.get("InstanceId")
            or route.get("NetworkInterfaceId")
            or route.get("EgressOnlyInternetGatewayId")
            or "?"
        )
        summary.append(f"  {destination} -> {target}")
    return summary


def _get_route_tables_for_subnet(subnet_id, rtbs):
    associated = []
    for rtb in rtbs:
        associations = rtb.get("Associations", [])
        for assoc in associations:
            if (
                assoc.get("SubnetId") == subnet_id
                and assoc.get("AssociationState", {}).get("State") == "associated"
            ):
                associated.append(rtb)
    return associated


class ControlNetworkFlowsWithRouteTablesCheck:
    def __init__(self):
        self.check_id = "control-network-flows-with-route-tables"
        self.check_name = "Control Network Flows with Route Tables"

    @property
    def question(self) -> str:
        return (
            "Are route tables used to restrict network traffic flows to only the flows "
            "necessary for each workload?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that route tables are used to restrict network "
            "traffic flows to only the flows necessary for each workload."
        )

    def run(self) -> CheckResult:
        rtb_analysis = _analyze()
        message = (
            "Below is a summary of each VPC and subnet with resources, including a "
            "summary of the route tables associated with each subnet.\n\n"
            f"{rtb_analysis}"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
