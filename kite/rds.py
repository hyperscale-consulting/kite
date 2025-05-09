"""RDS service module for Kite."""

from typing import List
from dataclasses import dataclass


@dataclass
class RDSInstance:
    """RDS instance data class."""

    instance_id: str
    engine: str
    region: str


def get_instances(session, region: str) -> List[RDSInstance]:
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

    response = rds_client.describe_db_instances()
    for instance in response.get("DBInstances", []):
        instances.append(
            RDSInstance(
                instance_id=instance.get("DBInstanceIdentifier"),
                engine=instance.get("Engine"),
                region=region,
            )
        )

    return instances
