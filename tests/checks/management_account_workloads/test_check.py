from unittest.mock import patch

import pytest

from kite.checks.management_account_workloads.check import (
    check_management_account_workloads,
)
from kite.data import save_ecs_clusters


@pytest.fixture
def workload_resources_in_mgmt_account(mgmt_account_id):
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


@pytest.fixture
def mock_prompt_user_with_panel():
    with patch(
        "kite.checks.management_account_workloads.check.prompt_user_with_panel"
    ) as mock:
        yield mock


def test_check_management_account_workloads_no_management_account(
    workload_resources_in_mgmt_account, config
):
    config.management_account_id = None
    result = check_management_account_workloads()

    assert result["check_id"] == "no-management-account-workloads"
    assert result["check_name"] == "No Management Account Workloads"
    assert result["status"] == "PASS"
    assert (
        "No management account ID provided in config, skipping check."
        in result["details"]["message"]
    )


def test_check_management_account_workloads_no_resources():
    result = check_management_account_workloads()

    # Verify the result
    assert result["check_id"] == "no-management-account-workloads"
    assert result["check_name"] == "No Management Account Workloads"
    assert result["status"] == "PASS"
    assert (
        "No workload resources found in the management account"
        in result["details"]["message"]
    )


def test_check_management_account_workloads_with_resources(
    workload_resources_in_mgmt_account,
    mock_prompt_user_with_panel,
):
    mock_prompt_user_with_panel.return_value = ("y", "All good")
    result = check_management_account_workloads()

    # Verify the result
    assert result["check_id"] == "no-management-account-workloads"
    assert result["check_name"] == "No Management Account Workloads"
    assert result["status"] == "PASS"
    assert (
        "The management account is free of workload resources."
        in result["details"]["message"]
    )
    _, kwargs = mock_prompt_user_with_panel.call_args
    assert (
        "The following workload resources were found in the management account:\n"
        "- ECS: (us-east-1) "
        "(clusterArn=arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster)\n"
    ) in kwargs.get("message", "")
