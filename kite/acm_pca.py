import boto3


def get_certificate_authorities(session: boto3.Session, region: str) -> list[dict[str, object]]:
    """
    Get all certificate authorities in a given region.
    """
    client = session.client("acm-pca", region_name=region)
    paginator = client.get_paginator("list_certificate_authorities")
    certificate_authorities = []
    for page in paginator.paginate():
        for authority in page["CertificateAuthorities"]:
            certificate_authorities.append(authority)
    return certificate_authorities
