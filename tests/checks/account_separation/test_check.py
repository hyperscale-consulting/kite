"""Test the account separation check."""

from unittest.mock import patch

import pytest

from kite.checks.account_separation.check import check_account_separation
from kite.helpers import get_organization_structure_str


def test_account_separation_check_no_org():
    """Test the account separation check when AWS Organizations is not in use."""
    result = check_account_separation()
    assert result["check_id"] == "account-separation"
    assert result["check_name"] == "Account Separation"
    assert result["status"] == "FAIL"
    assert "AWS Organizations is not being used" in result["details"]["message"]


@pytest.mark.parametrize(
    "expected_status,expected_message",
    [
        ("PASS", "Effective account separation is in place"),
        ("FAIL", "Account separation could be improved"),
    ],
)
def test_check_account_separation(organization, expected_status, expected_message):
    """Test the account separation check."""
    with patch(
        "kite.checks.account_separation.check.prompt_user_with_panel"
    ) as mock_prompt_user_with_panel:
        # Setup mocks
        mock_prompt_user_with_panel.return_value = (
            True if expected_status == "PASS" else False,
            {},
        )

        # Run the check
        result = check_account_separation()

        # Verify the result
        assert result["check_id"] == "account-separation"
        assert result["check_name"] == "Account Separation"
        assert result["status"] == expected_status
        assert expected_message in result["details"]["message"]

        # Check that the message contains the expected content
        expected_message_content = (
            "Consider the following factors for account separation:\n"
            "- Are unrelated workloads, or workloads with different data "
            "sensitivity, separated into different accounts?\n"
            "- Are dev, test, dev tooling, deployment, etc accounts "
            "separated from workload accounts?\n"
            "- Are there separate log archive and audit (AKA security "
            "tooling) accounts?\n\n"
            "Organization Structure:\n"
            f"{get_organization_structure_str(organization)}"
        )

        mock_prompt_user_with_panel.assert_called_once_with(
            check_name="Account Separation",
            message=expected_message_content,
            prompt="Is there effective account separation?",
            default=True,
        )
