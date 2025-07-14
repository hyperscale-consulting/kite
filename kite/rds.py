"""RDS service module for Kite."""

from dataclasses import dataclass


@dataclass
class RDSInstance:
    """RDS instance data class."""

    instance_id: str
    engine: str
    region: str


def get_instances(session, region: str) -> list[RDSInstance]:
    """
    Get all RDS instances in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of RDS instances
    """
    rds_client = session.client("rds", region_name=region)
    instances = []

    paginator = rds_client.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        instances.extend(page.get("DBInstances", []))

    return instances
