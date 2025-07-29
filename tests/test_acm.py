from collections import defaultdict

from botocore.exceptions import ClientError

from hyperscale.kite.acm import get_certificates


class ListCertificatesPaginator:
    def __init__(self, certificates, error_response=None):
        self.certificates = certificates
        self.error_response = error_response

    def paginate(self):
        if self.error_response:
            raise ClientError(self.error_response, "ListCertificates")
        # copy the certificates list, but only the CertificatArn and DomainName
        # attributes to match the list-certificates response
        certificates = [
            {"CertificateArn": c["CertificateArn"], "DomainName": c["DomainName"]}
            for c in self.certificates.values()
        ]
        return [{"CertificateSummaryList": certificates}]


class AcmClient:
    def __init__(self, error_code=None):
        self.error_response = error_code and {"Error": {"Code": error_code}} or None
        self.error_code = error_code
        self.certificates = defaultdict(dict)
        self.paginators = {
            "list_certificates": ListCertificatesPaginator(
                self.certificates, self.error_response
            ),
        }

    def get_paginator(self, operation_name):
        return self.paginators[operation_name]

    def describe_certificate(self, CertificateArn):
        return {"Certificate": self.certificates[CertificateArn]}

    def add_certificate(self, domain_name):
        arn = (
            "arn:aws:acm:us-east-1:123456789012:certificate/"
            f"a1b2c3d4-5678-90ab-cdef-{domain_name}"
        )
        self.certificates[arn] = {
            "CertificateArn": arn,
            "DomainName": domain_name,
            "Status": "ISSUED",
        }


def test_get_certificates(stub_aws_session):
    client = AcmClient()
    stub_aws_session.register_client(client, "acm", "eu-west-2")
    client.add_certificate("test.example.com")
    certificates = get_certificates(session=stub_aws_session, region="eu-west-2")
    assert len(certificates) == 1
    assert certificates[0]["DomainName"] == "test.example.com"


def test_get_certificates_no_subscription(stub_aws_session):
    client = AcmClient(error_code="SubscriptionRequiredException")
    stub_aws_session.register_client(client, "acm", "eu-west-2")
    certificates = get_certificates(session=stub_aws_session, region="eu-west-2")
    assert len(certificates) == 0
