import boto3
from botocore.exceptions import ClientError


def get_certificates(session: boto3.Session, region: str) -> list[dict]:
    try:
        acm_client = session.client("acm", region_name=region)
        paginator = acm_client.get_paginator("list_certificates")
        certificates = []
        for page in paginator.paginate():
            for certificate in page["CertificateSummaryList"]:
                certificate_details = acm_client.describe_certificate(
                    CertificateArn=certificate["CertificateArn"]
                )
                certificates.append(certificate_details["Certificate"])
        return certificates
    except ClientError as e:
        if e.response["Error"]["Code"] == "SubscriptionRequiredException":
            return []
        raise e
