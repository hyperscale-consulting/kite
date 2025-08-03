import json

import pytest

from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.vpc_endpoints_enforce_data_perimeter import (
    VpcEndpointsEnforceDataPerimeterCheck,
)
from hyperscale.kite.data import save_vpc_endpoints
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization_with_workload_account

workload_account_id = "123456789012"
org_id = "test-org"


def allow_all_policy():
    return dict(Statement=[dict(Effect="Allow", Action="*", Resource="*")])


def enforce_data_perimeter_policy():
    return dict(
        Statement=[
            dict(
                Effect="Allow",
                Action="*",
                Resource="*",
                Condition={
                    "StringEquals": {
                        "AWS:PrincipalOrgID": org_id,
                        "aws:ResourceOrgID": org_id,
                    }
                },
            ),
            dict(
                Effect="Allow",
                Action="*",
                Resource="*",
                Condition={"Bool": {"aws:PrincipalIsAWSService": "true"}},
            ),
        ]
    )


@pytest.fixture
def check():
    return VpcEndpointsEnforceDataPerimeterCheck()


def test_no_policies(check):
    create_config_for_org()
    create_organization_with_workload_account(
        workload_account_id=workload_account_id, organization_id=org_id
    )
    endpoint = dict(
        VpcEndpointId="vpce-01234567890abcdef0",
        VpcEndpointType="Interface",
        VpcId="vpc-01234567890abcdef0",
    )
    save_vpc_endpoints(workload_account_id, "eu-west-2", [endpoint])
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "Some VPC endpoints are missing required endpoint policies" in result.reason


def test_allow_all_policy(check):
    create_config_for_org()
    create_organization_with_workload_account(
        workload_account_id=workload_account_id, organization_id=org_id
    )
    endpoint = dict(
        VpcEndpointId="vpce-01234567890abcdef0",
        VpcEndpointType="Interface",
        VpcId="vpc-01234567890abcdef0",
        PolicyDocument=json.dumps(allow_all_policy()),
    )
    save_vpc_endpoints(workload_account_id, "eu-west-2", [endpoint])
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "Some VPC endpoints are missing required endpoint policies" in result.reason


def test_enforce_data_perimeter_policy(check):
    create_config_for_org()
    create_organization_with_workload_account(
        workload_account_id=workload_account_id, organization_id=org_id
    )
    endpoint = dict(
        VpcEndpointId="vpce-01234567890abcdef0",
        VpcEndpointType="Interface",
        VpcId="vpc-01234567890abcdef0",
        PolicyDocument=json.dumps(enforce_data_perimeter_policy()),
    )
    save_vpc_endpoints(workload_account_id, "eu-west-2", [endpoint])

    result = check.run()
    assert result.status == CheckStatus.PASS


def test_no_org(check):
    create_config_for_standalone_account()
    assert check.run().status == CheckStatus.FAIL
