from botocore.exceptions import ClientError

from hyperscale.kite.acm_pca import get_certificate_authorities


class ListCertificateAuthoritiesPaginator:
    def __init__(self, certificate_authorities, error_response=None):
        self.certificate_authorities = certificate_authorities
        self.error_response = error_response

    def paginate(self):
        if self.error_response:
            raise ClientError(self.error_response, "ListCertificateAuthorities")
        return [{"CertificateAuthorities": self.certificate_authorities}]


class AcmPcaClient:
    def __init__(self, error_code=None):
        self.certificate_authorities = []
        self.error_response = error_code and {"Error": {"Code": error_code}} or None
        self.paginators = {
            "list_certificate_authorities": ListCertificateAuthoritiesPaginator(
                self.certificate_authorities, self.error_response
            ),
        }

    def get_paginator(self, operation_name):
        return self.paginators[operation_name]

    def add_certificate_authority(self, certificate_authority_arn):
        self.certificate_authorities.append(
            {
                "Arn": certificate_authority_arn,
                "Status": "ACTIVE",
                "Type": "ROOT",
                "Serial": "1234567890",
                "CreatedAt": "2021-01-01T00:00:00Z",
            }
        )


def test_get_certificate_authorities(stub_aws_session):
    client = AcmPcaClient()
    stub_aws_session.register_client(client, "acm-pca", "eu-west-2")
    client.add_certificate_authority("123456789012")
    certificate_authorities = get_certificate_authorities(
        session=stub_aws_session, region="eu-west-2"
    )
    assert len(certificate_authorities) == 1
    assert certificate_authorities[0]["Arn"] == "123456789012"


def test_get_certificate_authorities_no_subscription(stub_aws_session):
    client = AcmPcaClient(error_code="SubscriptionRequiredException")
    stub_aws_session.register_client(client, "acm-pca", "eu-west-2")
    certificate_authorities = get_certificate_authorities(
        session=stub_aws_session, region="eu-west-2"
    )
    assert len(certificate_authorities) == 0
