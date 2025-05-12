"""EC2 service module for Kite."""

import boto3
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class EC2Instance:
    """EC2 instance data class."""

    instance_id: str
    instance_type: str
    state: str
    region: str


def get_running_instances(session, region: str) -> List[EC2Instance]:
    """
    Get all non-terminated EC2 instances in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of non-terminated EC2 instances
    """
    ec2_client = session.client("ec2", region_name=region)
    instances = []

    # Use paginator for describe_instances
    paginator = ec2_client.get_paginator("describe_instances")

    # Iterate through all pages
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                if instance.get("State", {}).get("Name") != "terminated":
                    instances.append(
                        EC2Instance(
                            instance_id=instance.get("InstanceId"),
                            instance_type=instance.get("InstanceType"),
                            state=instance.get("State", {}).get("Name"),
                            region=region,
                        )
                    )

    return instances


def get_key_pairs(session: boto3.Session) -> List[Dict[str, Any]]:
    """
    Get all EC2 key pairs in the account.

    Args:
        session: boto3 session to use for the API call

    Returns:
        List of dictionaries containing key pair information
    """
    ec2 = session.client('ec2')
    response = ec2.describe_key_pairs()
    return response.get('KeyPairs', [])
