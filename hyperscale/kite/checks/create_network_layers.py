from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.utils import get_name_from_tag
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_ec2_instances
from hyperscale.kite.data import get_ecs_clusters
from hyperscale.kite.data import get_efs_file_systems
from hyperscale.kite.data import get_eks_clusters
from hyperscale.kite.data import get_elbv2_load_balancers
from hyperscale.kite.data import get_lambda_functions
from hyperscale.kite.data import get_rds_instances
from hyperscale.kite.data import get_rtbs
from hyperscale.kite.data import get_subnets
from hyperscale.kite.data import get_vpcs
from hyperscale.kite.helpers import get_account_ids_in_scope


class CreateNetworkLayersCheck:
    def __init__(self):
        self.check_id = "create-network-layers"
        self.check_name = "Create Network Layers"

    @property
    def question(self) -> str:
        return (
            "Is your network topology segmented into different layers based on "
            "logical groupings of your workload components according to their "
            "data sensitivity and access requirements?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that your network is segmented into different layers "
            "based on logical groupings of your workload components according to their "
            "data sensitivity and access requirements."
        )

    def _is_subnet_private(self, subnet_id: str, route_tables: list[dict]) -> bool:
        for rtb in route_tables:
            associations = rtb.get("Associations", [])
            subnet_associated = False
            for assoc in associations:
                if (
                    assoc.get("SubnetId") == subnet_id
                    and assoc.get("AssociationState", {}).get("State") == "associated"
                ):
                    subnet_associated = True
                    break
            if not subnet_associated:
                continue
            routes = rtb.get("Routes", [])
            for route in routes:
                gateway_id = route.get("GatewayId", "")
                destination = route.get("DestinationCidrBlock", "")
                if gateway_id.startswith("igw-") and destination == "0.0.0.0/0":
                    return False
        return True

    def _get_resources_in_subnet(
        self,
        subnet_id: str,
        rds_instances,
        eks_clusters,
        ecs_clusters,
        ec2_instances,
        lambda_functions,
        efs_file_systems,
        elbv2_load_balancers,
    ) -> dict:
        resources = {
            "RDS": [],
            "EKS": [],
            "ECS": [],
            "EC2": [],
            "Lambda": [],
            "EFS": [],
            "ELBv2": [],
        }
        for rds in rds_instances:
            db_subnet_group = rds.get("DBSubnetGroup", {})
            subnets = db_subnet_group.get("Subnets", [])
            for subnet in subnets:
                if subnet.get("SubnetIdentifier") == subnet_id:
                    resources["RDS"].append(rds.get("DBInstanceIdentifier", "Unknown"))
                    break
        for eks in eks_clusters:
            vpc_config = eks.get("resourcesVpcConfig", {})
            subnet_ids = vpc_config.get("subnetIds", [])
            if subnet_id in subnet_ids:
                resources["EKS"].append(eks.get("name", "Unknown"))
        for ecs in ecs_clusters:
            services = ecs.get("services", [])
            for service in services:
                network_config = service.get("networkConfiguration", {})
                awsvpc_config = network_config.get("awsvpcConfiguration", {})
                subnets = awsvpc_config.get("subnets", [])
                if subnet_id in subnets:
                    cluster_name = ecs.get("clusterName", "Unknown")
                    service_name = service.get("serviceName", "Unknown")
                    resources["ECS"].append(f"{cluster_name}/{service_name}")
        for ec2 in ec2_instances:
            if ec2.get("SubnetId") == subnet_id:
                resources["EC2"].append(ec2.get("InstanceId", "Unknown"))
        for lambda_func in lambda_functions:
            vpc_config = lambda_func.get("VpcConfig", {})
            subnet_ids = vpc_config.get("SubnetIds", [])
            if subnet_id in subnet_ids:
                resources["Lambda"].append(lambda_func.get("FunctionName", "Unknown"))
        for efs in efs_file_systems:
            mount_targets = efs.get("MountTargets", [])
            for mount_target in mount_targets:
                if mount_target.get("SubnetId") == subnet_id:
                    resources["EFS"].append(
                        efs.get("Name", efs.get("FileSystemId", "Unknown"))
                    )
                    break
        for lb in elbv2_load_balancers:
            for az in lb.get("AvailabilityZones", []):
                if az.get("SubnetId") == subnet_id:
                    resources["ELBv2"].append(
                        lb.get("LoadBalancerName", lb.get("LoadBalancerArn", "Unknown"))
                    )
                    break
        return resources

    def _analyze_network_topology(self) -> str:
        accounts = get_account_ids_in_scope()
        config = Config.get()
        analysis = "Network Topology Analysis:\n\n"
        public_warnings = []
        lambdas_without_vpc = []
        for account_id in accounts:
            account_has_resources = False
            account_analysis = f"Account: {account_id}\n" + "=" * 50 + "\n"
            for region in config.active_regions:
                region_has_resources = False
                region_analysis = f"\nRegion: {region}\n" + "-" * 30 + "\n"
                vpcs = get_vpcs(account_id, region)
                route_tables = get_rtbs(account_id, region)
                subnets = get_subnets(account_id, region)
                rds_instances = get_rds_instances(account_id, region)
                eks_clusters = get_eks_clusters(account_id, region)
                ecs_clusters = get_ecs_clusters(account_id, region)
                ec2_instances = get_ec2_instances(account_id, region) or []
                lambda_functions = get_lambda_functions(account_id, region)
                efs_file_systems = get_efs_file_systems(account_id, region)
                elbv2_load_balancers = get_elbv2_load_balancers(account_id, region)
                for lambda_func in lambda_functions:
                    if "VpcConfig" not in lambda_func or not lambda_func.get(
                        "VpcConfig"
                    ):
                        lambdas_without_vpc.append(
                            f"{lambda_func.get('FunctionName', 'Unknown')} (account: "
                            f"{account_id}, region: {region})"
                        )
                if not vpcs:
                    continue
                for vpc in vpcs:
                    vpc_id = vpc.get("VpcId", "Unknown")
                    vpc_name = get_name_from_tag(vpc)
                    vpc_cidr = vpc.get("CidrBlock", "Unknown")
                    vpc_has_resources = False
                    vpc_analysis = f"\nVPC: {vpc_id}"
                    if vpc_name:
                        vpc_analysis += f" (Name: {vpc_name})"
                    vpc_analysis += f" - CIDR: {vpc_cidr}\n"
                    vpc_subnets = [s for s in subnets if s.get("VpcId") == vpc_id]
                    if not vpc_subnets:
                        continue
                    for subnet in vpc_subnets:
                        subnet_id = subnet.get("SubnetId", "Unknown")
                        subnet_name = get_name_from_tag(subnet)
                        subnet_cidr = subnet.get("CidrBlock", "Unknown")
                        availability_zone = subnet.get("AvailabilityZone", "Unknown")
                        is_private = self._is_subnet_private(subnet_id, route_tables)
                        subnet_type = "Private" if is_private else "Public"
                        resources = self._get_resources_in_subnet(
                            subnet_id,
                            rds_instances,
                            eks_clusters,
                            ecs_clusters,
                            ec2_instances,
                            lambda_functions,
                            efs_file_systems,
                            elbv2_load_balancers,
                        )
                        if not any(resources.values()):
                            continue
                        vpc_has_resources = True
                        region_has_resources = True
                        account_has_resources = True
                        vpc_analysis += f"  Subnet: {subnet_id}"
                        if subnet_name:
                            vpc_analysis += f" (Name: {subnet_name})"
                        vpc_analysis += (
                            f" - {subnet_type} - CIDR: {subnet_cidr} - "
                            f"AZ: {availability_zone}\n"
                        )
                        has_resources = False
                        for resource_type, resource_list in resources.items():
                            if resource_list:
                                has_resources = True
                                vpc_analysis += (
                                    f"    {resource_type}: {', '.join(resource_list)}\n"
                                )
                                if subnet_type == "Public" and resource_type in [
                                    "RDS",
                                    "EFS",
                                    "EKS",
                                    "ECS",
                                    "EC2",
                                    "Lambda",
                                ]:
                                    for res in resource_list:
                                        public_warnings.append(
                                            f"{resource_type} {res} in public subnet "
                                            f"{subnet_id} "
                                            f"(account: {account_id}, region: "
                                            f"{region}, vpc: {vpc_id})"
                                        )
                        if not has_resources:
                            vpc_analysis += "    No resources found in this subnet.\n"
                    if vpc_has_resources:
                        region_analysis += vpc_analysis
                if region_has_resources:
                    account_analysis += region_analysis
            if account_has_resources:
                analysis += account_analysis
        if lambdas_without_vpc:
            analysis += (
                "\n⚠️ The following Lambda functions are not deployed in a VPC "
                "(should be deployed in a VPC unless there's a good reason):\n"
            )
            for lambda_name in lambdas_without_vpc:
                analysis += f"  - {lambda_name}\n"
        if public_warnings:
            analysis += (
                "\n⚠️ The following resources are running in public subnets "
                "(should be private unless there's a good reason):\n"
            )
            for warning in public_warnings:
                analysis += f"  - {warning}\n"
        return analysis

    def run(self) -> CheckResult:
        network_analysis = self._analyze_network_topology()
        message = (
            "The analysis below shows:\n"
            "- Each VPC in each account and region\n"
            "- Each subnet and whether it's public or private\n"
            "- Resources deployed in each subnet\n"
            "- Lambda functions that should be deployed in VPC\n\n"
            "Consider the following factors:\n"
            "- Are your resources separated into different layers according to their "
            "data sensitivity and access requirements?\n"
            "- Are public-facing resources isolated from private resources?\n"
            "- Are data and application tiers separated?\n\n"
            f"{network_analysis}"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
