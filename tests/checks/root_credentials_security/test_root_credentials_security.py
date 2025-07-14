"""Tests for the root credentials security check."""

from unittest.mock import patch

from kite.checks.root_credentials_security.check import check_root_credentials_security


@patch("kite.checks.root_credentials_security.check.manual_check")
def test_check_root_credentials_security_pass(mock_manual_check):
    """Test that the check passes when the user confirms security measures are in
    place."""
    # Mock the manual_check function to return a PASS result
    mock_manual_check.return_value = {
        "check_id": "root-credentials-security",
        "check_name": "Root Credentials Security",
        "status": "PASS",
        "details": {
            "message": (
                "Root credentials are stored securely and accessed according to proper "
                "procedures."
            ),
        },
    }

    result = check_root_credentials_security()

    # Verify the result
    assert result["status"] == "PASS"
    assert (
        "Root credentials are stored securely and accessed according to proper "
        "procedures" in result["details"]["message"]
    )

    # Verify the manual_check was called correctly
    mock_manual_check.assert_called_once_with(
        check_id="root-credentials-security",
        check_name="Root Credentials Security",
        message=(
            "This check verifies that root credentials are stored securely and accessed "
            "according to proper procedures.\n\n"
            "Consider the following factors:\n"
            "- Are root credentials stored securely? (e.g., password manager for "
            "passwords, safe for MFA devices)\n"
            "- Is a two-person rule in place so that no single person has access to all "
            "necessary credentials for the root account?"
        ),
        prompt=(
            "Are root credentials stored securely and accessed according to proper "
            "procedures?"
        ),
        pass_message=(
            "Root credentials are stored securely and accessed according to proper "
            "procedures."
        ),
        fail_message=(
            "Root credentials storage or access procedures need improvement."
        ),
        default=True,
    )


@patch("kite.checks.root_credentials_security.check.manual_check")
def test_check_root_credentials_security_fail(mock_manual_check):
    """Test that the check fails when the user confirms security measures are not in
    place."""
    # Mock the manual_check function to return a FAIL result
    mock_manual_check.return_value = {
        "check_id": "root-credentials-security",
        "check_name": "Root Credentials Security",
        "status": "FAIL",
        "details": {
            "message": (
                "Root credentials storage or access procedures need improvement."
            ),
        },
    }

    result = check_root_credentials_security()

    # Verify the result
    assert result["status"] == "FAIL"
    assert (
        "Root credentials storage or access procedures need improvement"
        in result["details"]["message"]
    )

    # Verify the manual_check was called correctly
    mock_manual_check.assert_called_once()


@patch("kite.checks.root_credentials_security.check.manual_check")
def test_check_root_credentials_security_error(mock_manual_check):
    """Test that the check returns an error when an exception occurs."""
    # Mock the manual_check function to return an error result
    mock_manual_check.return_value = {
        "check_id": "root-credentials-security",
        "check_name": "Root Credentials Security",
        "status": "ERROR",
        "details": {
            "message": "Error checking root credentials security: Test error",
        },
    }

    result = check_root_credentials_security()

    # Verify the result
    assert result["status"] == "ERROR"
    assert "Error checking root credentials security" in result["details"]["message"]
