import pytest

from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.use_of_higher_level_services import (
    UseOfHigherLevelServicesCheck,
)
from hyperscale.kite.data import save_ec2_instances
from tests.factories import build_account
from tests.factories import build_ou
from tests.factories import create_config_for_org
from tests.factories import create_organization

mgmt_account_id = "123456789012"
workload1_account_id = "999999999999"
workload2_account_id = "666666666666"
region = "eu-west-2"


@pytest.fixture
def check():
    return UseOfHigherLevelServicesCheck()


def test_no_ec2_instances(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(
                    accounts=[
                        build_account(id=workload1_account_id),
                        build_account(id=workload2_account_id),
                    ]
                )
            ]
        ),
    )

    result = check.run()
    assert check.check_id == "use-of-higher-level-services"
    assert check.check_name == "Use of Higher-Level Services"
    assert result.status == CheckStatus.PASS
    assert "No EC2 instances" in result.reason


def test_ec2_instances_found(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(
                    accounts=[
                        build_account(id=workload1_account_id),
                        build_account(id=workload2_account_id),
                    ]
                )
            ]
        ),
    )
    instance1 = "i-1234567890abcdef0"
    instance2 = "i-1234567890abcdef1"
    instances = [
        {
            "InstanceId": instance1,
            "InstanceType": "t2.micro",
            "State": {"Name": "running"},
        },
        {
            "InstanceId": instance2,
            "InstanceType": "t2.micro",
            "State": {"Name": "running"},
        },
    ]
    save_ec2_instances(workload1_account_id, region, instances)

    result = check.run()
    assert check.check_id == "use-of-higher-level-services"
    assert check.check_name == "Use of Higher-Level Services"
    assert result.status == CheckStatus.MANUAL
    assert "EC2 instances were found" in result.context
    assert workload1_account_id in result.context
    assert workload2_account_id not in result.context
    assert instance1 in result.context
    assert instance2 in result.context
