from collections import defaultdict

from botocore.exceptions import ClientError

from hyperscale.kite.guardduty import get_detectors


class ListDetectorsPaginator:
    def __init__(self, detectors, error_response=None):
        self.detectors = detectors
        self.error_response = error_response

    def paginate(self):
        if self.error_response:
            raise ClientError(self.error_response, "ListDetectors")
        return [{"DetectorIds": list(self.detectors.keys())}]


class GuardDutyClient:
    def __init__(self, error_code=None):
        self.detectors = defaultdict(dict)
        self.error_response = error_code and {"Error": {"Code": error_code}} or None
        self.paginators = {
            "list_detectors": ListDetectorsPaginator(
                self.detectors, self.error_response
            ),
        }

    def get_paginator(self, operation_name):
        return self.paginators[operation_name]

    def get_detector(self, DetectorId):
        return self.detectors[DetectorId]

    def add_detector(self, detector_id, status):
        self.detectors[detector_id] = {
            "Status": status,
            "CreatedAt": "2021-01-01T00:00:00Z",
            "UpdatedAt": "2021-01-01T00:00:00Z",
            "FindingPublishingFrequency": "FIFTEEN_MINUTES",
            "DataSources": {
                "S3Logs": {"Status": "ENABLED"},
                "S3DataEvents": {"Status": "ENABLED"},
            },
            "ServiceRoleArn": "arn:aws:iam::123456789012:role/test",
            "Features": [{"Name": "S3_DATA_EVENTS", "Status": "ENABLED"}],
        }


def test_get_detectors(stub_aws_session):
    client = GuardDutyClient()
    stub_aws_session.register_client(client, "guardduty", "eu-west-2")
    client.add_detector("123456789012", "ENABLED")
    detectors = get_detectors(session=stub_aws_session, region="eu-west-2")
    assert len(detectors) == 1
    assert detectors[0]["DetectorId"] == "123456789012"
    assert detectors[0]["Status"] == "ENABLED"


def test_get_detectors_no_subscription(stub_aws_session):
    client = GuardDutyClient(error_code="SubscriptionRequiredException")
    stub_aws_session.register_client(client, "guardduty", "eu-west-2")
    detectors = get_detectors(session=stub_aws_session, region="eu-west-2")
    assert len(detectors) == 0
