"""Tests for the root access keys disallowed check."""

import json
from unittest.mock import MagicMock, patch

from kite.checks.root_access_keys_disallowed.check import (
    check_root_access_keys_disallowed,
    _is_root_access_keys_disallow_scp,
)


def test_is_root_access_keys_disallow_scp_no_condition():
    """Test that an SCP with no condition is considered valid."""
    scp_content = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "iam:CreateAccessKey",
                "Resource": "*",
            }
        ],
    }
    assert _is_root_access_keys_disallow_scp(scp_content) is True


def test_is_root_access_keys_disallow_scp_with_root_condition():
    """Test that an SCP with a root user condition is considered valid."""
    scp_content = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "iam:CreateAccessKey",
                "Resource": "*",
                "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:*:iam::*:root"}},
            }
        ],
    }
    assert _is_root_access_keys_disallow_scp(scp_content) is True


def test_is_root_access_keys_disallow_scp_with_non_root_condition():
    """Test that an SCP with a non-root user condition is not considered valid."""
    scp_content = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "iam:CreateAccessKey",
                "Resource": "*",
                "Condition": {
                    "ArnLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/*"}
                },
            }
        ],
    }
    assert _is_root_access_keys_disallow_scp(scp_content) is False


def test_is_root_access_keys_disallow_scp_with_multiple_actions():
    """Test that an SCP with multiple actions is considered valid if it includes iam:CreateAccessKey."""
    scp_content = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": [
                    "iam:CreateAccessKey",
                    "iam:DeleteAccessKey",
                ],
                "Resource": "*",
            }
        ],
    }
    assert _is_root_access_keys_disallow_scp(scp_content) is True


def test_is_root_access_keys_disallow_scp_with_multiple_statements():
    """Test that an SCP with multiple statements is considered valid if any deny iam:CreateAccessKey."""
    scp_content = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
            {
                "Effect": "Deny",
                "Action": "iam:CreateAccessKey",
                "Resource": "*",
            },
        ],
    }
    assert _is_root_access_keys_disallow_scp(scp_content) is True


def test_is_root_access_keys_disallow_scp_invalid_json():
    """Test that an SCP with invalid JSON is not considered valid."""
    scp_content = {"invalid": "json"}
    assert _is_root_access_keys_disallow_scp(scp_content) is False


@patch("kite.checks.root_access_keys_disallowed.check.get_organization")
def test_check_root_access_keys_disallowed_no_org(mock_get_org):
    """Test that the check fails when AWS Organizations is not being used."""
    mock_get_org.return_value = None
    result = check_root_access_keys_disallowed()
    assert result["status"] == "FAIL"
    assert "AWS Organizations is not being used" in result["details"]["message"]


@patch("kite.checks.root_access_keys_disallowed.check.get_organization")
def test_check_root_access_keys_disallowed_root_has_scp(mock_get_org):
    """Test that the check passes when the root OU has the required SCP."""
    mock_org = MagicMock()
    mock_root = MagicMock()
    mock_scp = MagicMock()
    mock_scp.content = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "iam:CreateAccessKey",
                    "Resource": "*",
                }
            ],
        }
    )
    mock_scp.id = "scp-123"
    mock_scp.name = "DisallowRootAccessKeys"
    mock_scp.arn = "arn:aws:organizations::123456789012:scp/scp-123"
    mock_root.scps = [mock_scp]
    mock_org.root = mock_root
    mock_get_org.return_value = mock_org

    result = check_root_access_keys_disallowed()
    assert result["status"] == "PASS"
    msg = "Root access keys disallow SCP is attached " "to the root OU"
    assert msg in result["details"]["message"]
    assert result["details"]["scp"]["id"] == "scp-123"


@patch("kite.checks.root_access_keys_disallowed.check.get_organization")
def test_check_root_access_keys_disallowed_top_level_ous_have_scp(mock_get_org):
    """Test that the check passes when all top-level OUs have the required SCP."""
    mock_org = MagicMock()
    mock_root = MagicMock()
    mock_ou1 = MagicMock()
    mock_ou2 = MagicMock()
    mock_scp = MagicMock()
    mock_scp.content = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "iam:CreateAccessKey",
                    "Resource": "*",
                }
            ],
        }
    )
    mock_ou1.name = "OU1"
    mock_ou2.name = "OU2"
    mock_ou1.scps = [mock_scp]
    mock_ou2.scps = [mock_scp]
    mock_root.scps = []
    mock_root.child_ous = [mock_ou1, mock_ou2]
    mock_org.root = mock_root
    mock_get_org.return_value = mock_org

    result = check_root_access_keys_disallowed()
    assert result["status"] == "PASS"
    msg = "Root access keys disallow SCP is attached " "to all top-level OUs"
    assert msg in result["details"]["message"]


@patch("kite.checks.root_access_keys_disallowed.check.get_organization")
def test_check_root_access_keys_disallowed_some_top_level_ous_missing_scp(mock_get_org):
    """Test that the check fails when some top-level OUs are missing the required SCP."""
    mock_org = MagicMock()
    mock_root = MagicMock()
    mock_ou1 = MagicMock()
    mock_ou2 = MagicMock()
    mock_scp = MagicMock()
    mock_scp.content = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "iam:CreateAccessKey",
                    "Resource": "*",
                }
            ],
        }
    )
    mock_ou1.name = "OU1"
    mock_ou2.name = "OU2"
    mock_ou1.scps = [mock_scp]
    mock_ou2.scps = []  # OU2 is missing the SCP
    mock_root.scps = []
    mock_root.child_ous = [mock_ou1, mock_ou2]
    mock_org.root = mock_root
    mock_get_org.return_value = mock_org

    result = check_root_access_keys_disallowed()
    assert result["status"] == "FAIL"
    assert "OU2" in result["details"]["message"]
    assert result["details"]["ous_without_scp"] == ["OU2"]


@patch("kite.checks.root_access_keys_disallowed.check.get_organization")
def test_check_root_access_keys_disallowed_no_top_level_ous(mock_get_org):
    """Test that the check fails when there are no top-level OUs and root has no SCP."""
    mock_org = MagicMock()
    mock_root = MagicMock()
    mock_root.scps = []
    mock_root.child_ous = []
    mock_org.root = mock_root
    mock_get_org.return_value = mock_org

    result = check_root_access_keys_disallowed()
    assert result["status"] == "FAIL"
    msg = "Root access keys disallow SCP is not attached " "to the root OU"
    assert msg in result["details"]["message"]


@patch("kite.checks.root_access_keys_disallowed.check.get_organization")
def test_check_root_access_keys_disallowed_error(mock_get_org):
    """Test that the check returns an error when an exception occurs."""
    mock_get_org.side_effect = Exception("Test error")
    result = check_root_access_keys_disallowed()
    assert result["status"] == "ERROR"
    msg = "Error checking root access keys disallow SCP"
    assert msg in result["details"]["message"]
