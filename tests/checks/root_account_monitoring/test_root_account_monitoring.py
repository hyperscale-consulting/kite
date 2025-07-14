"""Tests for the root account monitoring check."""

from unittest.mock import patch

from kite.checks.root_account_monitoring.check import check_root_account_monitoring


@patch("kite.checks.root_account_monitoring.check.manual_check")
def test_check_root_account_monitoring_yes_with_details(mock_manual_check):
    """Test that the check passes when the user confirms monitoring is in place."""
    # Mock the manual_check function to return a PASS result with procedures
    mock_manual_check.return_value = {
        "check_id": "root-account-monitoring",
        "check_name": "Root Account Monitoring",
        "status": "PASS",
        "details": {
            "message": (
                "Root account monitoring and response procedures are in place."
            ),
            "procedures": "We use CloudWatch alarms and have a 24/7 response team",
        },
    }

    result = check_root_account_monitoring()

    # Verify the result
    assert result["status"] == "PASS"
    assert (
        "Root account monitoring and response procedures are in place"
        in result["details"]["message"]
    )
    assert (
        result["details"]["procedures"]
        == "We use CloudWatch alarms and have a 24/7 response team"
    )

    # Verify the manual_check was called correctly
    mock_manual_check.assert_called_once_with(
        check_id="root-account-monitoring",
        check_name="Root Account Monitoring",
        message=(
            "This check verifies that there are systems and procedures in place to "
            "monitor for and respond to root account misuse.\n\n"
            "Consider the following factors:\n"
            "- Are there systems in place to monitor root account activity?\n"
            "- Are there procedures to respond to suspicious root account activity?\n"
            "- Are these procedures regularly tested and updated?"
        ),
        prompt=(
            "Are there systems and procedures in place to monitor for and respond to "
            "root account misuse?"
        ),
        pass_message=("Root account monitoring and response procedures are in place."),
        fail_message=(
            "Root account monitoring and response procedures are not in place."
        ),
        default=True,
    )


@patch("kite.checks.root_account_monitoring.check.manual_check")
def test_check_root_account_monitoring_yes_without_details(mock_manual_check):
    """Test that the check passes when the user confirms monitoring is in place but
    provides no details."""
    # Mock the manual_check function to return a PASS result with empty procedures
    mock_manual_check.return_value = {
        "check_id": "root-account-monitoring",
        "check_name": "Root Account Monitoring",
        "status": "PASS",
        "details": {
            "message": (
                "Root account monitoring and response procedures are in place."
            ),
            "info": "We use CloudWatch alarms and have a 24/7 response team",
        },
    }

    result = check_root_account_monitoring()

    # Verify the result
    assert result["status"] == "PASS"
    assert (
        "Root account monitoring and response procedures are in place"
        in result["details"]["message"]
    )
    assert (
        result["details"]["info"]
        == "We use CloudWatch alarms and have a 24/7 response team"
    )

    # Verify the manual_check was called correctly
    mock_manual_check.assert_called_once()


@patch("kite.checks.root_account_monitoring.check.manual_check")
def test_check_root_account_monitoring_no(mock_manual_check):
    """Test that the check fails when the user confirms monitoring is not in place."""
    # Mock the manual_check function to return a FAIL result
    mock_manual_check.return_value = {
        "check_id": "root-account-monitoring",
        "check_name": "Root Account Monitoring",
        "status": "FAIL",
        "details": {
            "message": (
                "Root account monitoring and response procedures are not in place."
            ),
        },
    }

    result = check_root_account_monitoring()

    # Verify the result
    assert result["status"] == "FAIL"
    assert (
        "Root account monitoring and response procedures are not in place"
        in result["details"]["message"]
    )

    # Verify the manual_check was called correctly
    mock_manual_check.assert_called_once()


@patch("kite.checks.root_account_monitoring.check.manual_check")
def test_check_root_account_monitoring_error(mock_manual_check):
    """Test that the check returns an error when an exception occurs."""
    # Mock the manual_check function to return an error result
    mock_manual_check.return_value = {
        "check_id": "root-account-monitoring",
        "check_name": "Root Account Monitoring",
        "status": "ERROR",
        "details": {
            "message": "Error checking root account monitoring: Test error",
        },
    }

    result = check_root_account_monitoring()

    # Verify the result
    assert result["status"] == "ERROR"
    assert "Error checking root account monitoring" in result["details"]["message"]
