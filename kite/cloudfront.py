"""CloudFront service module for Kite."""

from typing import Any

import boto3


def get_distributions(session) -> list[dict[str, Any]]:
    """
    Get all CloudFront distributions.

    Args:
        session: The boto3 session to use

    Returns:
        List of CloudFront distributions
    """
    cloudfront_client = session.client("cloudfront")
    distributions = []
    paginator = cloudfront_client.get_paginator("list_distributions")
    for page in paginator.paginate():
        for dist in page.get("DistributionList", {}).get("Items", []):
            distributions.append(dist)

    return distributions


def get_origin_access_identities(session):
    cf = session.client("cloudfront")
    paginator = cf.get_paginator("list_cloud_front_origin_access_identities")
    identities = []
    for page in paginator.paginate():
        identities.extend(
            page.get("CloudFrontOriginAccessIdentityList", {}).get("Items", [])
        )
    return identities


def get_distributions_by_web_acl(
    session: boto3.Session,
    web_acl_arn: str,
) -> list[dict[str, Any]]:
    """
    Get all CloudFront distributions by Web ACL.
    """
    client = session.client("cloudfront")
    response = client.list_distributions_by_web_acl_id(WebACLId=web_acl_arn)
    arns = [e["ARN"] for e in response.get("DistributionList", {}).get("Items", [])]
    return arns
