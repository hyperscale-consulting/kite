import boto3
from botocore.exceptions import ClientError


def get_firewalls(session: boto3.Session, region: str) -> list[dict[str, object]]:
    try:
        client = session.client("network-firewall", region_name=region)
        paginator = client.get_paginator("list_firewalls")
        firewalls = []
        for page in paginator.paginate():
            for firewall in page["Firewalls"]:
                detail = client.describe_firewall(FirewallArn=firewall["FirewallArn"])
                firewall["Detail"] = detail
                firewalls.append(firewall)
        return firewalls
    except ClientError as e:
        if e.response["Error"]["Code"] == "SubscriptionRequiredException":
            return []
        raise e
