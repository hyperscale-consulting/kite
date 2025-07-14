from typing import Any

import boto3


def get_trails(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """
    Get all CloudTrail trails in the account.
    """
    cloudtrail = session.client("cloudtrail", region_name=region)
    response = cloudtrail.describe_trails(includeShadowTrails=False)
    return response.get("trailList", [])
