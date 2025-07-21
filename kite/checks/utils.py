from typing import Any

from kite.data import get_ec2_instances
from kite.data import get_ecs_clusters
from kite.data import get_efs_file_systems
from kite.data import get_eks_clusters
from kite.data import get_elbv2_load_balancers
from kite.data import get_lambda_functions
from kite.data import get_rds_instances
from kite.data import get_subnets
from kite.data import get_vpcs


def get_name_from_tag(resource: dict[str, Any], default="") -> str:
    tags = resource.get("Tags", [])
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value", default)
    return default


def _is_rds_instance_in_subnet(rds_instance, subnet_id):
    subnets = rds_instance["DBSubnetGroup"]["Subnets"]
    return any(subnet["SubnetIdentifier"] == subnet_id for subnet in subnets)


def _is_eks_cluster_in_subnet(eks_cluster, subnet_id):
    subnet_ids = eks_cluster["resourcesVpcConfig"]["subnetIds"]
    return subnet_id in subnet_ids


def _is_ecs_service_in_subnet(ecs_service, subnet_id):
    subnet_ids = ecs_service["networkConfiguration"]["awsvpcConfiguration"]["subnets"]
    return subnet_id in subnet_ids


def _is_efs_in_subnet(efs, subnet_id):
    mount_targets = efs["MountTargets"]
    return any(mount_target["SubnetId"] == subnet_id for mount_target in mount_targets)


def _is_elbv2_in_subnet(elb, subnet_id):
    azs = elb["AvailabilityZones"]
    return any(az["SubnetId"] == subnet_id for az in azs)


def _get_resources_in_subnet(
    subnet_id,
    rds_instances,
    eks_clusters,
    ecs_clusters,
    ec2_instances,
    lambda_functions,
    efs_file_systems,
    elbv2_load_balancers,
):
    resources = {}
    rds_instances = [
        rds for rds in rds_instances if _is_rds_instance_in_subnet(rds, subnet_id)
    ]
    for rds in rds_instances:
        rds["Name"] = rds["DBInstanceIdentifier"]
        rds["SecurityGroupIds"] = [
            sg["VpcSecurityGroupId"] for sg in rds["VpcSecurityGroups"]
        ]
    if rds_instances:
        resources["RDS"] = rds_instances

    eks_clusters = [
        eks for eks in eks_clusters if _is_eks_cluster_in_subnet(eks, subnet_id)
    ]
    for eks in eks_clusters:
        eks["Name"] = eks["name"]
        vpc_config = eks["resourcesVpcConfig"]
        eks["SecurityGroupIds"] = vpc_config.get(
            "securityGroupIds", []
        ) + vpc_config.get("clusterSecurityGroupId", [])
    if eks_clusters:
        resources["EKS"] = eks_clusters

    ecs_services = [
        service
        for cluster in ecs_clusters
        for service in cluster["services"]
        if _is_ecs_service_in_subnet(service, subnet_id)
    ]
    for service in ecs_services:
        service["Name"] = service["serviceArn"]
        network_config = service.get("networkConfiguration", {})
        awsvpc_config = network_config.get("awsvpcConfiguration", {})
        service["SecurityGroupIds"] = awsvpc_config.get("securityGroups", [])
    if ecs_services:
        resources["ECS"] = ecs_services

    ec2_instances = [i for i in ec2_instances if i["SubnetId"] == subnet_id]
    for instance in ec2_instances:
        instance["Name"] = instance["InstanceId"]
        instance["SecurityGroupIds"] = [
            sg["GroupId"] for sg in instance.get("SecurityGroups", [])
        ]
    if ec2_instances:
        resources["EC2"] = ec2_instances

    functions = [
        func
        for func in lambda_functions
        if subnet_id in func.get("VpcConfig", {}).get("SubnetIds", [])
    ]
    for f in functions:
        f["Name"] = f["FunctionName"]
        vpc_config = f.get("VpcConfig", {})
        f["SecurityGroupIds"] = vpc_config.get("SecurityGroupIds", [])
    if functions:
        resources["Lambda"] = functions

    efs_file_systems = [
        efs for efs in efs_file_systems if _is_efs_in_subnet(efs, subnet_id)
    ]
    for efs in efs_file_systems:
        efs["Name"] = efs["Name"]
        mts = efs.get("MountTargets", [])
        sgs = []
        for mt in mts:
            sgs.extend(mt.get("SecurityGroups", []))
        efs["SecurityGroupIds"] = sgs
    if efs_file_systems:
        resources["EFS"] = efs_file_systems

    elbs = [lb for lb in elbv2_load_balancers if _is_elbv2_in_subnet(lb, subnet_id)]
    for elb in elbs:
        elb["Name"] = elb["LoadBalancerName"]
        elb["SecurityGroupIds"] = elb.get("SecurityGroups", [])
    if elbs:
        resources["ELBv2"] = elbs
    return resources


def get_vpcs_with_resources(account_id: str, region: str):
    vpcs = get_vpcs(account_id, region)
    if not vpcs:
        return []

    subnets = get_subnets(account_id, region)
    rds_instances = get_rds_instances(account_id, region)
    eks_clusters = get_eks_clusters(account_id, region)
    ecs_clusters = get_ecs_clusters(account_id, region)
    ec2_instances = get_ec2_instances(account_id, region) or []
    lambda_functions = get_lambda_functions(account_id, region)
    efs_file_systems = get_efs_file_systems(account_id, region)
    elbv2_load_balancers = get_elbv2_load_balancers(account_id, region)
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        vpc["Subnets"] = []
        vpc_subnets = [s for s in subnets if s["VpcId"] == vpc_id]
        for subnet in vpc_subnets:
            subnet_id = subnet["SubnetId"]
            resources = _get_resources_in_subnet(
                subnet_id,
                rds_instances,
                eks_clusters,
                ecs_clusters,
                ec2_instances,
                lambda_functions,
                efs_file_systems,
                elbv2_load_balancers,
            )
            if resources:
                subnet["Resources"] = resources
                vpc["Subnets"].append(subnet)
    return [vpc for vpc in vpcs if vpc["Subnets"]]
