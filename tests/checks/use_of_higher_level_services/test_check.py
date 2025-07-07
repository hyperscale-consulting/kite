"""Tests for the Use of Higher-Level Services check."""

from unittest.mock import patch

import pytest

from kite.checks.use_of_higher_level_services.check import (
    check_use_of_higher_level_services,
)
from kite.data import save_ec2_instances


@pytest.fixture
def some_ec2_instances(workload_account_id, organization):
    instances = [
        {
            "InstanceId": "i-1234567890abcdef0",
            "InstanceType": "t2.micro",
            "State": {"Name": "running"},
        },
        {
            "InstanceId": "i-1234567890abcdef1",
            "InstanceType": "t2.micro",
            "State": {"Name": "running"},
        },
    ]
    save_ec2_instances(workload_account_id, "eu-west-2", instances)
    return instances


def test_check_use_of_higher_level_services_no_instances(organization):
    """Test the check when no EC2 instances are found."""
    result = check_use_of_higher_level_services()

    assert result["check_id"] == "use-of-higher-level-services"
    assert result["check_name"] == "Use of Higher-Level Services"
    assert result["status"] == "PASS"
    assert "No EC2 instances found" in result["details"]["message"]


def test_check_use_of_higher_level_services_with_instances_pass(some_ec2_instances):
    """Test the check when EC2 instances are found and user confirms good practices."""

    with patch(
        "kite.checks.use_of_higher_level_services.check.manual_check",
        return_value={
            "check_id": "use-of-higher-level-services",
            "check_name": "Use of Higher-Level Services",
            "status": "PASS",
            "details": {
                "message": "Higher-level managed services are favored over lower-level services such as EC2.",
            },
        },
    ):
        result = check_use_of_higher_level_services()

    assert result["check_id"] == "use-of-higher-level-services"
    assert result["check_name"] == "Use of Higher-Level Services"
    assert result["status"] == "PASS"
    assert "Higher-level managed services are favored" in result["details"]["message"]


def test_check_use_of_higher_level_services_with_instances_fail(some_ec2_instances):
    """Test the check when EC2 instances are found and user indicates improvement needed."""
    with patch(
        "kite.checks.use_of_higher_level_services.check.manual_check",
        return_value={
            "check_id": "use-of-higher-level-services",
            "check_name": "Use of Higher-Level Services",
            "status": "FAIL",
            "details": {
                "message": "Consider migrating workloads to higher-level managed services where possible.",
            },
        },
    ):
        result = check_use_of_higher_level_services()

    assert result["check_id"] == "use-of-higher-level-services"
    assert result["check_name"] == "Use of Higher-Level Services"
    assert result["status"] == "FAIL"
    assert "Consider migrating workloads" in result["details"]["message"]
