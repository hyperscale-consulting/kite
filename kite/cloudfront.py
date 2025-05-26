"""CloudFront service module for Kite."""

from typing import List
from dataclasses import dataclass


@dataclass
class CloudFrontDistribution:
    """CloudFront distribution data class."""

    distribution_id: str
    domain_name: str


def get_distributions(session) -> List[CloudFrontDistribution]:
    """
    Get all CloudFront distributions.

    Args:
        session: The boto3 session to use

    Returns:
        List of CloudFront distributions
    """
    cloudfront_client = session.client("cloudfront")
    distributions = []

    response = cloudfront_client.list_distributions()
    for dist in response.get("DistributionList", {}).get("Items", []):
        distributions.append(
            CloudFrontDistribution(
                distribution_id=dist.get("Id"),
                domain_name=dist.get("DomainName", "No domain name"),
            )
        )

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
