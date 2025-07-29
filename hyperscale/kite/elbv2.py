from typing import Any

import boto3


def get_load_balancers(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    client = session.client("elbv2", region_name=region)
    paginator = client.get_paginator("describe_load_balancers")
    load_balancers = []
    for page in paginator.paginate():
        for lb in page["LoadBalancers"]:
            lb["Attributes"] = get_load_balancer_attributes(
                session, lb["LoadBalancerArn"], region
            )
            load_balancers.append(lb)

    return load_balancers


def get_load_balancer_attributes(
    session: boto3.Session, load_balancer_arn: str, region: str
) -> dict[str, Any]:
    client = session.client("elbv2", region_name=region)
    response = client.describe_load_balancer_attributes(
        LoadBalancerArn=load_balancer_arn
    )
    result = {}
    attributes = response["Attributes"]
    for attribute in attributes:
        result[attribute["Key"]] = attribute["Value"]
    return result
