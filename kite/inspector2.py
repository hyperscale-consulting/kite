import boto3


def get_configuration(session: boto3.Session, region: str) -> dict[str, object]:
    """
    Get the configuration for a given account and region.
    """
    client = session.client("inspector2", region_name=region)
    try:
        response = client.get_configuration()
        return {
            "ec2Configuration": response["ec2Configuration"],
            "ecrConfiguration": response["ecrConfiguration"],
        }
    except client.exceptions.ResourceNotFoundException:
        return {}


def get_coverage(session: boto3.Session, region: str) -> list[dict[str, object]]:
    """
    Get the coverage for a given account and region.
    """
    client = session.client("inspector2", region_name=region)
    paginator = client.get_paginator("list_coverage")
    coverage = []
    for page in paginator.paginate():
        coverage.extend(page["coveredResources"])
    return coverage
