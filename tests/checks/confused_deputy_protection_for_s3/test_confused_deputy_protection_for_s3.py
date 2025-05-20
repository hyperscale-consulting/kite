"""Tests for the confused deputy protection for S3 check."""

import json
import pytest
from unittest.mock import patch

from kite.checks.confused_deputy_protection_for_s3.check import (
    check_confused_deputy_protection_for_s3,
    _has_confused_deputy_protection,
)
from kite.models import ControlPolicy, Organization, OrganizationalUnit


@pytest.fixture
def valid_rcp():
    """Return a valid RCP for confused deputy protection."""
    return ControlPolicy(
        id="p-1234567890",
        name="S3ConfusedDeputyProtection",
        arn="arn:aws:organizations::aws:policy/p-1234567890",
        description="Valid confused deputy protection policy",
        type="RESOURCE_CONTROL_POLICY",
        content=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["s3:*"],
                "Resource": "*",
                "Condition": {
                    "StringNotEqualsIfExists": {
                        "aws:SourceOrgID": "o-1234567890"
                    },
                    "Null": {
                        "aws:SourceAccount": "false"
                    },
                    "Bool": {
                        "aws:PrincipalIsAWSService": "true"
                    }
                }
            }]
        })
    )


@pytest.fixture
def invalid_rcp():
    """Return an invalid RCP for confused deputy protection."""
    return ControlPolicy(
        id="p-0987654321",
        name="InvalidS3Protection",
        arn="arn:aws:organizations::aws:policy/p-0987654321",
        description="Invalid confused deputy protection policy",
        type="RESOURCE_CONTROL_POLICY",
        content=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:*"],
                "Resource": "*"
            }]
        })
    )


def test_has_confused_deputy_protection_valid(valid_rcp):
    """Test that a valid RCP is correctly identified."""
    assert _has_confused_deputy_protection(valid_rcp, "o-1234567890")


def test_has_confused_deputy_protection_invalid(invalid_rcp):
    """Test that an invalid RCP is correctly identified."""
    assert not _has_confused_deputy_protection(invalid_rcp, "o-1234567890")


def test_has_confused_deputy_protection_invalid_json():
    """Test that invalid JSON is handled correctly."""
    invalid_policy = ControlPolicy(
        id="p-1234567890",
        name="InvalidJSON",
        arn="arn:aws:organizations::aws:policy/p-1234567890",
        description="Invalid JSON policy",
        type="RESOURCE_CONTROL_POLICY",
        content="invalid json"
    )
    assert not _has_confused_deputy_protection(invalid_policy, "o-1234567890")


@patch("kite.checks.confused_deputy_protection_for_s3.check.get_organization")
def test_check_confused_deputy_protection_for_s3_root_ou(mock_get_org, valid_rcp):
    """Test that the check passes when the root OU has the required RCP."""
    mock_get_org.return_value = Organization(
        id="o-1234567890",
        master_account_id="123456789012",
        arn="arn:aws:organizations::123456789012:organization/o-1234567890",
        feature_set="ALL",
        root=OrganizationalUnit(
            id="ou-1234567890",
            name="Root",
            arn="arn:aws:organizations::123456789012:organization/o-1234567890",
            scps=[],
            rcps=[valid_rcp],
            child_ous=[],
            accounts=[]
        )
    )

    result = check_confused_deputy_protection_for_s3()
    assert result["status"] == "PASS"
    assert "root OU" in result["details"]["message"]


@patch("kite.checks.confused_deputy_protection_for_s3.check.get_organization")
def test_check_confused_deputy_protection_for_s3_top_level_ous(mock_get_org, valid_rcp):
    """Test that the check passes when all top-level OUs have the required RCP."""
    mock_get_org.return_value = Organization(
        id="o-1234567890",
        master_account_id="123456789012",
        arn="arn:aws:organizations::123456789012:organization/o-1234567890",
        feature_set="ALL",
        root=OrganizationalUnit(
            id="ou-1234567890",
            name="Root",
            arn="arn:aws:organizations::123456789012:organization/o-1234567890",
            scps=[],
            rcps=[],
            child_ous=[
                OrganizationalUnit(
                    id="ou-0987654321",
                    name="OU1",
                    arn="arn:aws:organizations::123456789012:ou/o-1234567890/ou-0987654321",
                    scps=[],
                    rcps=[valid_rcp],
                    child_ous=[],
                    accounts=[]
                ),
                OrganizationalUnit(
                    id="ou-1122334455",
                    name="OU2",
                    arn="arn:aws:organizations::123456789012:ou/o-1234567890/ou-1122334455",
                    scps=[],
                    rcps=[valid_rcp],
                    child_ous=[],
                    accounts=[]
                )
            ],
            accounts=[]
        )
    )

    result = check_confused_deputy_protection_for_s3()
    assert result["status"] == "PASS"
    assert "top-level OUs" in result["details"]["message"]


@patch("kite.checks.confused_deputy_protection_for_s3.check.get_organization")
def test_check_confused_deputy_protection_for_s3_missing_protection(mock_get_org, valid_rcp, invalid_rcp):
    """Test that the check fails when some top-level OUs are missing the required RCP."""
    mock_get_org.return_value = Organization(
        id="o-1234567890",
        master_account_id="123456789012",
        arn="arn:aws:organizations::123456789012:organization/o-1234567890",
        feature_set="ALL",
        root=OrganizationalUnit(
            id="ou-1234567890",
            name="Root",
            arn="arn:aws:organizations::123456789012:organization/o-1234567890",
            scps=[],
            rcps=[],
            child_ous=[
                OrganizationalUnit(
                    id="ou-0987654321",
                    name="OU1",
                    arn="arn:aws:organizations::123456789012:ou/o-1234567890/ou-0987654321",
                    scps=[],
                    rcps=[valid_rcp],
                    child_ous=[],
                    accounts=[]
                ),
                OrganizationalUnit(
                    id="ou-1122334455",
                    name="OU2",
                    arn="arn:aws:organizations::123456789012:ou/o-1234567890/ou-1122334455",
                    scps=[],
                    rcps=[invalid_rcp],
                    child_ous=[],
                    accounts=[]
                )
            ],
            accounts=[]
        )
    )

    result = check_confused_deputy_protection_for_s3()
    assert result["status"] == "FAIL"
    assert "OU2" in result["details"]["message"]


@patch("kite.checks.confused_deputy_protection_for_s3.check.get_organization")
def test_check_confused_deputy_protection_for_s3_no_org(mock_get_org):
    """Test that the check fails when AWS Organizations is not being used."""
    mock_get_org.return_value = None

    result = check_confused_deputy_protection_for_s3()
    assert result["status"] == "FAIL"
    assert "AWS Organizations is not being used" in result["details"]["message"]


@patch("kite.checks.confused_deputy_protection_for_s3.check.get_organization")
def test_check_confused_deputy_protection_for_s3_no_top_level_ous(mock_get_org):
    """Test that the check fails when there are no top-level OUs and root OU has no protection."""
    mock_get_org.return_value = Organization(
        id="o-1234567890",
        master_account_id="123456789012",
        arn="arn:aws:organizations::123456789012:organization/o-1234567890",
        feature_set="ALL",
        root=OrganizationalUnit(
            id="ou-1234567890",
            name="Root",
            arn="arn:aws:organizations::123456789012:organization/o-1234567890",
            scps=[],
            rcps=[],
            child_ous=[],
            accounts=[]
        )
    )

    result = check_confused_deputy_protection_for_s3()
    assert result["status"] == "FAIL"
    assert "no top-level OUs" in result["details"]["message"]
