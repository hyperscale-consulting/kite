"""CloudFront service module for Kite."""

from typing import List, Dict, Any


def get_distributions(session) -> List[Dict[str, Any]]:
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
