"""Tests for the delegated admins for security services check."""

import pytest
from kite.checks.delegated_admins.check import check_delegated_admins_security_services
from kite.models import DelegatedAdmin
from kite.data import save_delegated_admins


@pytest.fixture
def mock_prompt_user_with_panel(mocker):
    """Mock the prompt_user_with_panel function."""
    return mocker.patch("kite.checks.delegated_admins.check.prompt_user_with_panel")


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
def delegated_admins_all_services(audit_account):
    admins = [
        delegated_admin(audit_account, "securityhub.amazonaws.com"),
        delegated_admin(audit_account, "inspector2.amazonaws.com"),
        delegated_admin(audit_account, "macie.amazonaws.com"),
        delegated_admin(audit_account, "detective.amazonaws.com"),
        delegated_admin(audit_account, "guardduty.amazonaws.com"),
    ]
    save_delegated_admins(admins)
    return admins


@pytest.fixture
def no_delegated_admins():
    admins = []
    save_delegated_admins(admins)
    return admins


@pytest.fixture
def only_guardduty_delegated_admin(audit_account):
    admins = [
        delegated_admin(audit_account, "guardduty.amazonaws.com"),
    ]
    save_delegated_admins(admins)
    return admins


def test_check_delegated_admins_security_services_all_services(
    delegated_admins_all_services, mock_prompt_user_with_panel
):
    """Test when all security services have delegated admins."""

    # Mock the user response
    mock_prompt_user_with_panel.return_value = (True, None)

    # Run the check
    result = check_delegated_admins_security_services()

    # Verify the result
    assert result["check_id"] == "delegated-admin-for-security-services"
    assert result["check_name"] == "Delegated admin for security services"
    assert result["status"] == "PASS"
    assert (
        "Delegated administrators for security services are set to the "
        "security tooling account."
    ) in result["details"]["message"]
    assert "delegated_admins" in result["details"]


def test_check_delegated_admins_user_says_no(
    delegated_admins_all_services, mock_prompt_user_with_panel
):
    """Test when all security services have delegated admins."""

    # Mock the user response
    mock_prompt_user_with_panel.return_value = (False, None)

    # Run the check
    result = check_delegated_admins_security_services()

    # Verify the result
    assert result["check_id"] == "delegated-admin-for-security-services"
    assert result["check_name"] == "Delegated admin for security services"
    assert result["status"] == "FAIL"
    assert (
        "Delegated administrators for security services are not set to the "
        "security tooling account."
    ) in result["details"]["message"]
    assert "delegated_admins" in result["details"]


def test_check_delegated_admins_security_services_no_delegated_admins(
    no_delegated_admins, mock_prompt_user_with_panel
):
    """Test when no delegated admins are found."""

    # Run the check
    result = check_delegated_admins_security_services()

    # Verify the result
    assert result["check_id"] == "delegated-admin-for-security-services"
    assert result["check_name"] == "Delegated admin for security services"
    assert result["status"] == "FAIL"
    assert (
        "No delegated administrators found for any services."
        in result["details"]["message"]
    )


def test_check_delegated_admins_security_services_only_guardduty_delegated_admin(
    only_guardduty_delegated_admin, mock_prompt_user_with_panel
):
    """Test when only GuardDuty has a delegated admin."""

    # Mock the user response
    mock_prompt_user_with_panel.return_value = (True, None)

    # Run the check
    result = check_delegated_admins_security_services()

    # Verify the result
    assert result["check_id"] == "delegated-admin-for-security-services"
    assert result["check_name"] == "Delegated admin for security services"
    assert result["status"] == "FAIL"
    assert (
        "The following security services do not have delegated administrators: "
        "securityhub.amazonaws.com, inspector2.amazonaws.com, macie.amazonaws.com, "
        "detective.amazonaws.com"
        in result["details"]["message"]
    )
