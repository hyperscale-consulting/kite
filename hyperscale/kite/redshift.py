from botocore.exceptions import ClientError


def get_clusters(session, region: str) -> list[dict]:
    """
    Get all Redshift clusters in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of Redshift clusters
    """
    redshift_client = session.client("redshift", region_name=region)
    try:
        response = redshift_client.describe_clusters()
        return response.get("Clusters", [])
    except ClientError as e:
        if e.response["Error"]["Code"] == "OptInRequired":
            return []
        else:
            raise e
