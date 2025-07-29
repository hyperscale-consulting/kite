import boto3
from botocore.exceptions import ClientError


def get_certificate_authorities(
    session: boto3.Session, region: str
) -> list[dict[str, object]]:
    try:
        client = session.client("acm-pca", region_name=region)
        paginator = client.get_paginator("list_certificate_authorities")
        certificate_authorities = []
        for page in paginator.paginate():
            for authority in page["CertificateAuthorities"]:
                certificate_authorities.append(authority)
        return certificate_authorities
    except ClientError as e:
        if e.response["Error"]["Code"] == "SubscriptionRequiredException":
            return []
        raise e
