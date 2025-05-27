import json

import pytest

from kite.checks.vpc_endpoints_enforce_data_perimeter.check import (
    check_vpc_endpoints_enforce_data_perimeter,
)
from kite.data import save_vpc_endpoints


@pytest.fixture
def allow_all_policy():
    return dict(
        Statement=[
            dict(
                Effect="Allow",
                Action="*",
                Resource="*"
            )
        ]
    )


@pytest.fixture
def enforce_data_perimeter_policy(organization):
    return dict(
        Statement=[
            dict(
                Effect="Allow",
                Action="*",
                Resource="*",
                Condition={
                    "StringEquals": {
                        "AWS:PrincipalOrgID": organization.id,
                        "aws:ResourceOrgID": organization.id
                    }
                }
            ),
            dict(
                Effect="Allow",
                Action="*",
                Resource="*",
                Condition={
                    "Bool": {
                        "aws:PrincipalIsAWSService": "true"
                    }
                }
            )
        ]
    )


@pytest.fixture
def vpc_endpoint_no_policy(workload_account_id, organization):
    endpoint = dict(
        VpcEndpointId="vpce-01234567890abcdef0",
        VpcEndpointType="Interface",
        VpcId="vpc-01234567890abcdef0"
    )
    save_vpc_endpoints(workload_account_id, 'eu-west-2', [endpoint])
    yield endpoint


@pytest.fixture
def vpc_endpoint_allow_all_policy(allow_all_policy, workload_account_id, organization):
    endpoint = dict(
        VpcEndpointId="vpce-01234567890abcdef0",
        VpcEndpointType="Interface",
        VpcId="vpc-01234567890abcdef0",
        PolicyDocument=json.dumps(allow_all_policy)
    )
    save_vpc_endpoints(workload_account_id, 'eu-west-2', [endpoint])
    yield endpoint


@pytest.fixture
def vpc_endpoint_enforce_data_perimeter_policy(enforce_data_perimeter_policy,
                                               workload_account_id, organization):
    endpoint = dict(
        VpcEndpointId="vpce-01234567890abcdef0",
        VpcEndpointType="Interface",
        VpcId="vpc-01234567890abcdef0",
        PolicyDocument=json.dumps(enforce_data_perimeter_policy)
    )
    save_vpc_endpoints(workload_account_id, 'eu-west-2', [endpoint])
    yield endpoint


def test_no_policies(vpc_endpoint_no_policy):
    result = check_vpc_endpoints_enforce_data_perimeter()
    assert result["status"] == "FAIL"


def test_allow_all_policy(vpc_endpoint_allow_all_policy):
    result = check_vpc_endpoints_enforce_data_perimeter()
    assert result["status"] == "FAIL"


def test_enforce_data_perimeter_policy(vpc_endpoint_enforce_data_perimeter_policy):
    result = check_vpc_endpoints_enforce_data_perimeter()
    assert result["status"] == "PASS"
