"""Tests for the Trusted Delegated Admins check."""

from unittest.mock import patch

import pytest

from kite.data import save_delegated_admins
from kite.checks.trusted_delegated_admins.check import check_trusted_delegated_admins
from kite.organizations import DelegatedAdmin


@pytest.fixture
def mock_prompt_user_with_panel(mocker):
    """Mock the prompt_user_with_panel function."""
    return mocker.patch("kite.checks.trusted_delegated_admins.check.prompt_user_with_panel")


def delegated_admin(account, service_principal):
    return DelegatedAdmin(
        id=account.id,
        arn=account.arn,
        name=account.name,
        email=account.email,
        status=account.status,
        joined_method=account.joined_method,
        joined_timestamp=account.joined_timestamp,
        delegation_enabled_date='2021-01-01T00:00:00Z',
        service_principal=service_principal
    )


@pytest.fixture
def delegated_admins(audit_account, workload_account):
    admins = [
        delegated_admin(audit_account, "securityhub.amazonaws.com"),
        delegated_admin(audit_account, "inspector2.amazonaws.com"),
        delegated_admin(audit_account, "macie.amazonaws.com"),
        delegated_admin(workload_account, "detective.amazonaws.com"),
        delegated_admin(workload_account, "guardduty.amazonaws.com"),
    ]
    save_delegated_admins(admins)
    return admins


@pytest.fixture
def no_delegated_admins():
    admins = []
    save_delegated_admins(admins)
    return admins


def test_check_trusted_delegated_admins_no_admins(no_delegated_admins):
    """Test the check when no delegated admins are found."""
    result = check_trusted_delegated_admins()

    # Verify the result
    assert result["check_id"] == "trusted-delegated-admins"
    assert result["check_name"] == "Trusted Delegated Admins"
    assert result["status"] == "PASS"
    assert result["message"] == "No delegated admins found."
    assert result["details"] == {}


def test_check_trusted_delegated_admins_pass(delegated_admins, mock_prompt_user_with_panel):
    """Test the check when all delegated admins are trusted."""

    mock_prompt_user_with_panel.return_value = (True, None)
    result = check_trusted_delegated_admins()

    # Verify the result
    assert result["check_id"] == "trusted-delegated-admins"
    assert result["check_name"] == "Trusted Delegated Admins"
    assert result["status"] == "PASS"
    assert result["message"] == "All delegated admins are trusted accounts."
    assert "delegated_admins" in result["details"]
    assert len(result["details"]["delegated_admins"]) == 2


def test_check_trusted_delegated_admins_fail(delegated_admins, mock_prompt_user_with_panel):
    """Test the check when some delegated admins are not trusted."""

    mock_prompt_user_with_panel.return_value = (False, None)
    result = check_trusted_delegated_admins()

    # Verify the result
    assert result["check_id"] == "trusted-delegated-admins"
    assert result["check_name"] == "Trusted Delegated Admins"
    assert result["status"] == "FAIL"
    assert result["message"] == "Some delegated admins may not be trusted accounts."
    assert "delegated_admins" in result["details"]
    assert len(result["details"]["delegated_admins"]) == 2
