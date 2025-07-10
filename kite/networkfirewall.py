import boto3


def get_firewalls(session: boto3.Session, region: str) -> list[dict[str, object]]:
    client = session.client("network-firewall", region_name=region)
    paginator = client.get_paginator("list_firewalls")
    firewalls = []
    for page in paginator.paginate():
        for firewall in page["Firewalls"]:
            detail = client.describe_firewall(FirewallArn=firewall["FirewallArn"])
            firewall["Detail"] = detail
            firewalls.append(firewall)
    return firewalls
