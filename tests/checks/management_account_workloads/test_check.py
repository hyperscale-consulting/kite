"""Tests for the Management Account Workloads check."""

from unittest.mock import patch, MagicMock

import pytest

from kite.models import WorkloadResources, WorkloadResource
from kite.data import save_mgmt_account_workload_resources

from kite.checks.management_account_workloads.check import (
    check_management_account_workloads,
)


@pytest.fixture
def workload_resources_in_mgmt_account():
    resources = WorkloadResources(
        resources=[
            WorkloadResource(resource_type="ECS", resource_id="test-cluster",
                             region="us-east-1"),
        ]
    )
    save_mgmt_account_workload_resources(resources)
    return resources


@pytest.fixture
def no_workload_resources():
    resources = WorkloadResources(
        resources=[]
    )
    save_mgmt_account_workload_resources(resources)
    return resources


def test_check_management_account_workloads_no_management_account(
        workload_resources_in_mgmt_account, config
):
    """Test the check when no management account ID is provided."""
    config.management_account_id = None
    result = check_management_account_workloads()

    # Verify the result
    assert result["check_id"] == "no-management-account-workloads"
    assert result["check_name"] == "No Management Account Workloads"
    assert result["status"] == "PASS"
    assert (
        "No management account ID provided in config, skipping check."
        in result["details"]["message"]
    )


def test_check_management_account_workloads_no_resources(no_workload_resources):
    """Test the check when no resources are found in the management account."""
    result = check_management_account_workloads()

    # Verify the result
    assert result["check_id"] == "no-management-account-workloads"
    assert result["check_name"] == "No Management Account Workloads"
    assert result["status"] == "PASS"
    assert (
        "No workload resources found in the management account"
        in result["details"]["message"]
    )


def test_check_management_account_workloads_with_resources_pass(
        workload_resources_in_mgmt_account
):
    """Test the check when resources are found but user confirms no workloads."""
    with patch(
        "kite.checks.management_account_workloads.check.prompt_user_with_panel",
        return_value=(True, {}),
    ):
        result = check_management_account_workloads()

    # Verify the result
    assert result["check_id"] == "no-management-account-workloads"
    assert result["check_name"] == "No Management Account Workloads"
    assert result["status"] == "PASS"
    assert (
        "The management account is free of workload resources."
        in result["details"]["message"]
    )


def test_check_management_account_workloads_with_resources_fail(
        workload_resources_in_mgmt_account
):
    """Test the check when resources are found and user confirms workloads exist."""
    with patch(
        "kite.checks.management_account_workloads.check.prompt_user_with_panel",
        return_value=(False, {}),
    ):
        result = check_management_account_workloads()

    # Verify the result
    assert result["check_id"] == "no-management-account-workloads"
    assert result["check_name"] == "No Management Account Workloads"
    assert result["status"] == "FAIL"
    assert (
        "The management account contains workload resources."
        in result["details"]["message"]
    )
    assert (
        "Consider moving these resources to a dedicated workload account."
        in result["details"]["message"]
    )
