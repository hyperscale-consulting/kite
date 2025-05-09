"""Tests for the Use of Higher-Level Services check."""

from unittest.mock import patch, MagicMock

from kite.checks.use_of_higher_level_services.check import check_use_of_higher_level_services


def test_check_use_of_higher_level_services_no_accounts():
    """Test the check when no accounts are in scope."""
    with patch(
        "kite.checks.use_of_higher_level_services.check.get_account_ids_in_scope",
        return_value=[],
    ):
        result = check_use_of_higher_level_services()

    assert result["check_id"] == "use-of-higher-level-services"
    assert result["check_name"] == "Use of Higher-Level Services"
    assert result["status"] == "FAIL"
    assert "No accounts in scope found" in result["details"]["message"]


def test_check_use_of_higher_level_services_no_instances():
    """Test the check when no EC2 instances are found."""
    mock_session = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"Reservations": []}]

    mock_ec2_client = MagicMock()
    mock_ec2_client.get_paginator.return_value = mock_paginator

    mock_session.client.return_value = mock_ec2_client

    # Mock Config for active regions
    mock_config = MagicMock()
    mock_config.active_regions = ["us-east-1"]

    with patch(
        "kite.checks.use_of_higher_level_services.check.get_account_ids_in_scope",
        return_value=["123456789012"],
    ):
        with patch(
            "kite.checks.use_of_higher_level_services.check.assume_role",
            return_value=mock_session,
        ):
            with patch(
                "kite.checks.use_of_higher_level_services.check.Config.get",
                return_value=mock_config,
            ):
                result = check_use_of_higher_level_services()

    assert result["check_id"] == "use-of-higher-level-services"
    assert result["check_name"] == "Use of Higher-Level Services"
    assert result["status"] == "PASS"
    assert "No EC2 instances found" in result["details"]["message"]


def test_check_use_of_higher_level_services_with_instances_pass():
    """Test the check when EC2 instances are found and user confirms good practices."""
    mock_session = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{
        "Reservations": [{
            "Instances": [{
                "InstanceId": "i-1234567890abcdef0",
                "State": {"Name": "running"},
            }]
        }]
    }]

    mock_ec2_client = MagicMock()
    mock_ec2_client.get_paginator.return_value = mock_paginator

    mock_session.client.return_value = mock_ec2_client

    # Mock Config for active regions
    mock_config = MagicMock()
    mock_config.active_regions = ["us-east-1"]

    with patch(
        "kite.checks.use_of_higher_level_services.check.get_account_ids_in_scope",
        return_value=["123456789012"],
    ):
        with patch(
            "kite.checks.use_of_higher_level_services.check.assume_role",
            return_value=mock_session,
        ):
            with patch(
                "kite.checks.use_of_higher_level_services.check.Config.get",
                return_value=mock_config,
            ):
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


def test_check_use_of_higher_level_services_with_instances_fail():
    """Test the check when EC2 instances are found and user indicates improvement needed."""
    mock_session = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{
        "Reservations": [{
            "Instances": [{
                "InstanceId": "i-1234567890abcdef0",
                "State": {"Name": "running"},
            }]
        }]
    }]

    mock_ec2_client = MagicMock()
    mock_ec2_client.get_paginator.return_value = mock_paginator

    mock_session.client.return_value = mock_ec2_client

    # Mock Config for active regions
    mock_config = MagicMock()
    mock_config.active_regions = ["us-east-1"]

    with patch(
        "kite.checks.use_of_higher_level_services.check.get_account_ids_in_scope",
        return_value=["123456789012"],
    ):
        with patch(
            "kite.checks.use_of_higher_level_services.check.assume_role",
            return_value=mock_session,
        ):
            with patch(
                "kite.checks.use_of_higher_level_services.check.Config.get",
                return_value=mock_config,
            ):
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


def test_check_use_of_higher_level_services_multiple_instances():
    """Test the check with multiple EC2 instances across different accounts and regions."""
    mock_session = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{
        "Reservations": [{
            "Instances": [
                {
                    "InstanceId": "i-1234567890abcdef0",
                    "State": {"Name": "running"},
                },
                {
                    "InstanceId": "i-0987654321fedcba0",
                    "State": {"Name": "stopped"},
                },
                {
                    "InstanceId": "i-terminated",
                    "State": {"Name": "terminated"},  # Should be excluded
                }
            ]
        }]
    }]

    mock_ec2_client = MagicMock()
    mock_ec2_client.get_paginator.return_value = mock_paginator

    mock_session.client.return_value = mock_ec2_client

    # Mock Config for active regions
    mock_config = MagicMock()
    mock_config.active_regions = ["us-east-1", "us-west-2"]

    with patch(
        "kite.checks.use_of_higher_level_services.check.get_account_ids_in_scope",
        return_value=["123456789012", "210987654321"],
    ):
        with patch(
            "kite.checks.use_of_higher_level_services.check.assume_role",
            return_value=mock_session,
        ):
            with patch(
                "kite.checks.use_of_higher_level_services.check.Config.get",
                return_value=mock_config,
            ):
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


def test_check_use_of_higher_level_services_error():
    """Test the check when an error occurs."""
    with patch(
        "kite.checks.use_of_higher_level_services.check.get_account_ids_in_scope",
        side_effect=Exception("Test error"),
    ):
        result = check_use_of_higher_level_services()

    assert result["check_id"] == "use-of-higher-level-services"
    assert result["check_name"] == "Use of Higher-Level Services"
    assert result["status"] == "ERROR"
    assert "Error checking use of higher-level services: Test error" in result["details"]["message"]
