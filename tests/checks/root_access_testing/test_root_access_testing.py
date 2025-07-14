"""Tests for the root access testing check."""

from unittest.mock import patch

from kite.checks.root_access_testing.check import check_root_access_testing


@patch("kite.checks.root_access_testing.check.manual_check")
def test_check_root_access_testing_pass(mock_manual_check):
    """Test that the check passes when the user confirms testing procedures are in
    place."""
    # Mock the manual_check function to return a PASS result
    mock_manual_check.return_value = {
        "check_id": "root-access-testing",
        "check_name": "Root Access Testing",
        "status": "PASS",
        "details": {
            "message": (
                "Root user access is periodically tested to ensure it is functioning in "
                "emergency situations."
            ),
        },
    }

    result = check_root_access_testing()

    # Verify the result
    assert result["status"] == "PASS"
    assert (
        "Root user access is periodically tested to ensure it is functioning in "
        "emergency situations" in result["details"]["message"]
    )

    # Verify the manual_check was called correctly
    mock_manual_check.assert_called_once_with(
        check_id="root-access-testing",
        check_name="Root Access Testing",
        message=(
            "This check verifies that root user access is periodically tested to ensure "
            "it is functioning in emergency situations.\n\n"
            "Consider the following factors:\n"
            "- Is root user access tested on a regular schedule?\n"
            "- Does the testing include both password and MFA device verification?\n"
            "- Is the testing process documented and include emergency procedures?"
        ),
        prompt=(
            "Is root user access periodically tested to ensure it is functioning in "
            "emergency situations?"
        ),
        pass_message=(
            "Root user access is periodically tested to ensure it is functioning in "
            "emergency situations."
        ),
        fail_message=("Root user access testing procedures need improvement."),
        default=True,
    )


@patch("kite.checks.root_access_testing.check.manual_check")
def test_check_root_access_testing_fail(mock_manual_check):
    """Test that the check fails when the user confirms testing procedures are not in
    place."""
    # Mock the manual_check function to return a FAIL result
    mock_manual_check.return_value = {
        "check_id": "root-access-testing",
        "check_name": "Root Access Testing",
        "status": "FAIL",
        "details": {
            "message": ("Root user access testing procedures need improvement."),
        },
    }

    result = check_root_access_testing()

    # Verify the result
    assert result["status"] == "FAIL"
    assert (
        "Root user access testing procedures need improvement"
        in result["details"]["message"]
    )

    # Verify the manual_check was called correctly
    mock_manual_check.assert_called_once()


@patch("kite.checks.root_access_testing.check.manual_check")
def test_check_root_access_testing_error(mock_manual_check):
    """Test that the check returns an error when an exception occurs."""
    # Mock the manual_check function to return an error result
    mock_manual_check.return_value = {
        "check_id": "iam-008",
        "check_name": "Root Access Testing",
        "status": "ERROR",
        "details": {
            "message": "Error checking root access testing: Test error",
        },
    }

    result = check_root_access_testing()

    # Verify the result
    assert result["status"] == "ERROR"
    assert "Error checking root access testing" in result["details"]["message"]
