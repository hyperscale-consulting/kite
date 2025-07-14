"""Tests for the Region Deny SCP check."""

from unittest.mock import MagicMock
from unittest.mock import patch

from kite.checks.region_deny_scp.check import check_region_deny_scp
from kite.organizations import ControlPolicy
from kite.organizations import Organization
from kite.organizations import OrganizationalUnit


def test_check_region_deny_scp_pass_root():
    """Test the check when region deny SCP is attached to root OU."""
    # Create mock organization with root OU having region deny SCP
    mock_root_ou = OrganizationalUnit(
        id="r-example123",
        arn=("arn:aws:organizations::111111111111:root/o-example123/r-example123"),
        name="Root",
        accounts=[],
        child_ous=[],
        scps=[
            ControlPolicy(
                id="p-example123",
                arn=(
                    "arn:aws:organizations::111111111111:policy/o-example123/"
                    "p-example123"
                ),
                name="RegionDenySCP",
                description="Denies access to all regions except allowed ones",
                content=(
                    '{"Version":"2012-10-17","Statement":[{"Effect":"Deny",'
                    '"Action":"*","Resource":"*","Condition":{"StringNotEquals":'
                    '{"aws:RequestedRegion":["us-east-1","us-west-2"]}}}]}'
                ),
                type="SERVICE_CONTROL_POLICY",
            )
        ],
    )

    mock_org = Organization(
        id="o-example123",
        master_account_id="111111111111",
        arn=("arn:aws:organizations::111111111111:organization/o-example123"),
        feature_set="ALL",
        root=mock_root_ou,
    )

    # Mock the get_organization function to return our mock organization
    with (
        patch(
            "kite.checks.region_deny_scp.check.get_organization", return_value=mock_org
        ),
        patch(
            "kite.checks.region_deny_scp.check.Config.get",
            return_value=MagicMock(active_regions=["us-east-1", "us-west-2"]),
        ),
    ):
        result = check_region_deny_scp()

    # Verify the result
    assert result["check_id"] == "region-deny-scp"
    assert result["check_name"] == "Region Deny SCP"
    assert result["status"] == "PASS"
    assert "Region deny SCP is attached to the root OU" in result["details"]["message"]


def test_check_region_deny_scp_pass_top_level_ous():
    """Test the check when region deny SCP is attached to all top-level OUs."""
    # Create mock organization with top-level OUs having region deny SCP
    mock_ou1 = OrganizationalUnit(
        id="ou-example123",
        arn=("arn:aws:organizations::111111111111:ou/o-example123/ou-example123"),
        name="OU1",
        accounts=[],
        child_ous=[],
        scps=[
            ControlPolicy(
                id="p-example123",
                arn=(
                    "arn:aws:organizations::111111111111:policy/o-example123/"
                    "p-example123"
                ),
                name="RegionDenySCP",
                description="Denies access to all regions except allowed ones",
                content=(
                    '{"Version":"2012-10-17","Statement":[{"Effect":"Deny",'
                    '"Action":"*","Resource":"*","Condition":{"StringNotEquals":'
                    '{"aws:RequestedRegion":["us-east-1","us-west-2"]}}}]}'
                ),
                type="SERVICE_CONTROL_POLICY",
            )
        ],
    )

    mock_ou2 = OrganizationalUnit(
        id="ou-example456",
        arn=("arn:aws:organizations::111111111111:ou/o-example123/ou-example456"),
        name="OU2",
        accounts=[],
        child_ous=[],
        scps=[
            ControlPolicy(
                id="p-example123",
                arn=(
                    "arn:aws:organizations::111111111111:policy/o-example123/"
                    "p-example123"
                ),
                name="RegionDenySCP",
                description="Denies access to all regions except allowed ones",
                content=(
                    '{"Version":"2012-10-17","Statement":[{"Effect":"Deny",'
                    '"Action":"*","Resource":"*","Condition":{"StringNotEquals":'
                    '{"aws:RequestedRegion":["us-east-1","us-west-2"]}}}]}'
                ),
                type="SERVICE_CONTROL_POLICY",
            )
        ],
    )

    mock_root_ou = OrganizationalUnit(
        id="r-example123",
        arn=("arn:aws:organizations::111111111111:root/o-example123/r-example123"),
        name="Root",
        accounts=[],
        child_ous=[mock_ou1, mock_ou2],
        scps=[],
    )

    mock_org = Organization(
        id="o-example123",
        master_account_id="111111111111",
        arn=("arn:aws:organizations::111111111111:organization/o-example123"),
        feature_set="ALL",
        root=mock_root_ou,
    )

    # Mock the get_organization function to return our mock organization
    with (
        patch(
            "kite.checks.region_deny_scp.check.get_organization", return_value=mock_org
        ),
        patch(
            "kite.checks.region_deny_scp.check.Config.get",
            return_value=MagicMock(active_regions=["us-east-1", "us-west-2"]),
        ),
    ):
        result = check_region_deny_scp()

    # Verify the result
    assert result["check_id"] == "region-deny-scp"
    assert result["check_name"] == "Region Deny SCP"
    assert result["status"] == "PASS"
    assert (
        "Region deny SCP is attached to all top-level OUs"
        in result["details"]["message"]
    )


def test_check_region_deny_scp_fail_no_scp():
    """Test the check when no region deny SCP is found."""
    # Create mock organization with no region deny SCP
    mock_root_ou = OrganizationalUnit(
        id="r-example123",
        arn=("arn:aws:organizations::111111111111:root/o-example123/r-example123"),
        name="Root",
        accounts=[],
        child_ous=[],
        scps=[],
    )

    mock_org = Organization(
        id="o-example123",
        master_account_id="111111111111",
        arn=("arn:aws:organizations::111111111111:organization/o-example123"),
        feature_set="ALL",
        root=mock_root_ou,
    )

    # Mock the get_organization function to return our mock organization
    with (
        patch(
            "kite.checks.region_deny_scp.check.get_organization", return_value=mock_org
        ),
        patch(
            "kite.checks.region_deny_scp.check.Config.get",
            return_value=MagicMock(active_regions=["us-east-1", "us-west-2"]),
        ),
    ):
        result = check_region_deny_scp()

    # Verify the result
    assert result["check_id"] == "region-deny-scp"
    assert result["check_name"] == "Region Deny SCP"
    assert result["status"] == "FAIL"
    assert (
        "Region deny SCP is not attached to the root OU and there are no top-level OUs"
        in result["details"]["message"]
    )


def test_check_region_deny_scp_fail_missing_ou():
    """Test the check when some top-level OUs are missing region deny SCP."""
    # Create mock organization with one top-level OU missing region deny SCP
    mock_ou1 = OrganizationalUnit(
        id="ou-example123",
        arn=("arn:aws:organizations::111111111111:ou/o-example123/ou-example123"),
        name="OU1",
        accounts=[],
        child_ous=[],
        scps=[
            ControlPolicy(
                id="p-example123",
                arn=(
                    "arn:aws:organizations::111111111111:policy/o-example123/"
                    "p-example123"
                ),
                name="RegionDenySCP",
                description="Denies access to all regions except allowed ones",
                content=(
                    '{"Version":"2012-10-17","Statement":[{"Effect":"Deny",'
                    '"Action":"*","Resource":"*","Condition":{"StringNotEquals":'
                    '{"aws:RequestedRegion":["us-east-1","us-west-2"]}}}]}'
                ),
                type="SERVICE_CONTROL_POLICY",
            )
        ],
    )

    mock_ou2 = OrganizationalUnit(
        id="ou-example456",
        arn=("arn:aws:organizations::111111111111:ou/o-example123/ou-example456"),
        name="OU2",
        accounts=[],
        child_ous=[],
        scps=[],
    )

    mock_root_ou = OrganizationalUnit(
        id="r-example123",
        arn=("arn:aws:organizations::111111111111:root/o-example123/r-example123"),
        name="Root",
        accounts=[],
        child_ous=[mock_ou1, mock_ou2],
        scps=[],
    )

    mock_org = Organization(
        id="o-example123",
        master_account_id="111111111111",
        arn=("arn:aws:organizations::111111111111:organization/o-example123"),
        feature_set="ALL",
        root=mock_root_ou,
    )

    # Mock the get_organization function to return our mock organization
    with (
        patch(
            "kite.checks.region_deny_scp.check.get_organization", return_value=mock_org
        ),
        patch(
            "kite.checks.region_deny_scp.check.Config.get",
            return_value=MagicMock(active_regions=["us-east-1", "us-west-2"]),
        ),
    ):
        result = check_region_deny_scp()

    # Verify the result
    assert result["check_id"] == "region-deny-scp"
    assert result["check_name"] == "Region Deny SCP"
    assert result["status"] == "FAIL"
    assert (
        "Region deny SCP is not attached to the root OU or all top-level OUs"
        in result["details"]["message"]
    )
    assert "OU2" in result["details"]["message"]


def test_check_region_deny_scp_no_org():
    """Test the check when AWS Organizations is not in use."""
    # Mock the get_organization function to return None
    with patch("kite.checks.region_deny_scp.check.get_organization", return_value=None):
        result = check_region_deny_scp()

    # Verify the result
    assert result["check_id"] == "region-deny-scp"
    assert result["check_name"] == "Region Deny SCP"
    assert result["status"] == "FAIL"
    assert "AWS Organizations is not being used" in result["details"]["message"]


def test_check_region_deny_scp_no_active_regions():
    """Test the check when no active regions are configured."""
    # Create mock organization
    mock_root_ou = OrganizationalUnit(
        id="r-example123",
        arn=("arn:aws:organizations::111111111111:root/o-example123/r-example123"),
        name="Root",
        accounts=[],
        child_ous=[],
        scps=[],
    )

    mock_org = Organization(
        id="o-example123",
        master_account_id="111111111111",
        arn=("arn:aws:organizations::111111111111:organization/o-example123"),
        feature_set="ALL",
        root=mock_root_ou,
    )

    # Mock the get_organization function to return our mock organization
    with (
        patch(
            "kite.checks.region_deny_scp.check.get_organization", return_value=mock_org
        ),
        patch(
            "kite.checks.region_deny_scp.check.Config.get",
            return_value=MagicMock(active_regions=[]),
        ),
    ):
        result = check_region_deny_scp()

    # Verify the result
    assert result["check_id"] == "region-deny-scp"
    assert result["check_name"] == "Region Deny SCP"
    assert result["status"] == "FAIL"
    assert "No active regions configured" in result["details"]["message"]


def test_check_region_deny_scp_error():
    """Test the check when an error occurs."""
    # Mock the get_organization function to raise an exception
    with patch(
        "kite.checks.region_deny_scp.check.get_organization",
        side_effect=Exception("Test error"),
    ):
        result = check_region_deny_scp()

    # Verify the result
    assert result["check_id"] == "region-deny-scp"
    assert result["check_name"] == "Region Deny SCP"
    assert result["status"] == "ERROR"
    assert "Error checking region deny SCP" in result["details"]["message"]
