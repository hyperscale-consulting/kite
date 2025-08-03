from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks.management_account_workloads import (
    ManagementAccountWorkloadsCheck,
)
from hyperscale.kite.data import save_ecs_clusters
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization

mgmt_account_id = "123456789012"


def workload_resources_in_mgmt_account():
    save_ecs_clusters(
        mgmt_account_id,
        "us-east-1",
        [
            {
                "clusterName": "test-cluster",
                "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster",
            }
        ],
    )


def test_check_management_account_workloads_no_management_account():
    create_config_for_standalone_account()
    result = ManagementAccountWorkloadsCheck().run()

    assert result.status == CheckStatus.PASS
    assert result.reason is not None
    assert (
        "No management account ID provided in config, skipping check." in result.reason
    )


def test_check_management_account_workloads_no_resources():
    create_config_for_org()
    result = ManagementAccountWorkloadsCheck().run()

    assert result.status == CheckStatus.PASS
    assert result.reason is not None
    assert "No workload resources found in the management account" in result.reason


def test_check_management_account_workloads_with_resources():
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(mgmt_account_id=mgmt_account_id)
    workload_resources_in_mgmt_account()
    result = ManagementAccountWorkloadsCheck().run()

    assert result.status == CheckStatus.MANUAL
    assert result.context is not None
    assert (
        "The following workload resources were found in the management account:\n"
        "- ECS: (us-east-1) "
        "(clusterArn=arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster)\n"
    ) in result.context
