"""Tests for the organizations module."""

from datetime import datetime
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from kite.organizations import build_ou_structure
from kite.organizations import ControlPolicy
from kite.organizations import DelegatedAdmin
from kite.organizations import fetch_delegated_admins
from kite.organizations import fetch_organization
from kite.organizations import Organization
from kite.organizations import OrganizationalUnit


@pytest.fixture
def mock_orgs_client():
    """Create a mock organizations client."""
    return MagicMock()


@pytest.fixture
def mock_session(mock_orgs_client):
    """Create a mock session with organizations client."""
    mock_session = MagicMock()
    mock_session.client.return_value = mock_orgs_client
    return mock_session


@pytest.fixture
def mock_org_response():
    """Create a mock organization response."""
    return {
        "Organization": {
            "Id": "o-exampleorgid",
            "MasterAccountId": "123456789012",
            "Arn": ("arn:aws:organizations::123456789012:organization/o-exampleorgid"),
            "FeatureSet": "ALL",
        }
    }


@pytest.fixture
def mock_roots_response():
    """Create a mock roots response."""
    return {
        "Roots": [
            {
                "Id": "r-examplerootid",
                "Arn": (
                    "arn:aws:organizations::123456789012:root/o-exampleorgid/r-examplerootid"
                ),
                "Name": "Root",
            }
        ]
    }


@pytest.fixture
def mock_policies_for_target_response():
    """Create a mock policies for target response."""
    return {
        "Policies": [
            {
                "Id": "p-examplepolicyid1",
                "Arn": (
                    "arn:aws:organizations::123456789012:policy/o-exampleorgid/"
                    "p-examplepolicyid1"
                ),
                "Name": "DenyAllPolicy",
                "Type": "SERVICE_CONTROL_POLICY",
            }
        ]
    }


@pytest.fixture
def mock_policy_details_response():
    """Create a mock policy details response."""
    return {
        "Policy": {
            "PolicySummary": {
                "Id": "p-examplepolicyid1",
                "Arn": (
                    "arn:aws:organizations::123456789012:policy/o-exampleorgid/"
                    "p-examplepolicyid1"
                ),
                "Name": "DenyAllPolicy",
                "Description": "Denies all actions",
                "Type": "SERVICE_CONTROL_POLICY",
                "AwsManaged": False,
            },
            "Content": (
                '{"Version":"2012-10-17","Statement":[{"Effect":"Deny",'
                '"Action":"*","Resource":"*"}]}'
            ),
        }
    }


@pytest.fixture
def mock_policies_for_target_paginator(mock_policies_for_target_response):
    """Create a mock policies for target paginator."""
    mock_paginator = MagicMock()

    def paginate_side_effect(**kwargs):
        if kwargs.get("Filter") == "SERVICE_CONTROL_POLICY":
            return [mock_policies_for_target_response]
        else:
            return [{"Policies": []}]

    mock_paginator.paginate.side_effect = paginate_side_effect
    return mock_paginator


@pytest.fixture
def mock_accounts_response():
    """Create a mock accounts response."""
    return {
        "Accounts": [
            {
                "Id": "123456789012",
                "Arn": (
                    "arn:aws:organizations::123456789012:account/o-example123/123456789012"
                ),
                "Email": "admin@example.com",
                "Name": "Management Account",
                "Status": "ACTIVE",
                "JoinedMethod": "CREATED",
                "JoinedTimestamp": datetime(2023, 1, 1),
            },
            {
                "Id": "098765432109",
                "Arn": (
                    "arn:aws:organizations::123456789012:account/o-example123/098765432109"
                ),
                "Email": "dev@example.com",
                "Name": "Development Account",
                "Status": "ACTIVE",
                "JoinedMethod": "INVITED",
                "JoinedTimestamp": datetime(2023, 1, 2),
            },
        ]
    }


@pytest.fixture
def mock_ou_response():
    """Create a mock OU response."""
    return {
        "OrganizationalUnit": {
            "Id": "ou-exampleouid1",
            "Arn": (
                "arn:aws:organizations::123456789012:ou/o-exampleorgid/ou-exampleouid1"
            ),
            "Name": "OU 1",
        }
    }


@pytest.fixture
def mock_accounts_paginator(mock_accounts_response):
    """Create a mock accounts paginator."""
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [mock_accounts_response]
    return mock_paginator


@pytest.fixture
def mock_child_ous_response():
    """Create a mock child OUs response."""
    return {
        "Children": [
            {
                "Id": "ou-exampleouid1",
                "Type": "ORGANIZATIONAL_UNIT",
            },
            {
                "Id": "ou-exampleouid2",
                "Type": "ORGANIZATIONAL_UNIT",
            },
        ]
    }


@pytest.fixture
def mock_children_paginator(mock_child_ous_response):
    """Create a mock children paginator."""
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [mock_child_ous_response]
    return mock_paginator


@pytest.fixture
def mock_delegated_admins_response():
    """Create a mock delegated administrators response."""
    return {
        "DelegatedAdministrators": [
            {
                "Id": "123456789012",
                "Arn": (
                    "arn:aws:organizations::123456789012:account/o-example123/123456789012"
                ),
            }
        ]
    }


@pytest.fixture
def mock_account_details_response():
    """Create a mock account details response."""
    return {
        "Account": {
            "Id": "123456789012",
            "Arn": (
                "arn:aws:organizations::123456789012:account/o-example123/123456789012"
            ),
            "Email": "security@example.com",
            "Name": "Security Account",
            "Status": "ACTIVE",
            "JoinedMethod": "INVITED",
            "JoinedTimestamp": datetime(2023, 1, 1),
        }
    }


@pytest.fixture
def mock_delegated_services_response():
    """Create a mock delegated services response."""
    return {
        "DelegatedServices": [
            {
                "ServicePrincipal": "securityhub.amazonaws.com",
                "DelegationEnabledDate": datetime(2023, 1, 1),
            },
            {
                "ServicePrincipal": "inspector2.amazonaws.com",
                "DelegationEnabledDate": datetime(2023, 1, 1),
            },
        ]
    }


@pytest.fixture
def mock_delegated_admins_paginator(mock_delegated_admins_response):
    """Create a mock delegated administrators paginator."""
    paginator = MagicMock()
    paginator.paginate.return_value = [mock_delegated_admins_response]
    return paginator


@pytest.fixture
def mock_delegated_services_paginator(mock_delegated_services_response):
    """Create a mock delegated services paginator."""
    paginator = MagicMock()
    paginator.paginate.return_value = [mock_delegated_services_response]
    return paginator


def test_fetch_organization_success(
    mock_session,
    mock_orgs_client,
    mock_org_response,
    mock_roots_response,
    mock_ou_response,
    mock_accounts_paginator,
    mock_children_paginator,
    mock_policies_for_target_paginator,
    mock_policy_details_response,
):
    """Test fetching organization structure successfully."""
    # Set up mocks
    mock_orgs_client.describe_organization.return_value = mock_org_response
    mock_orgs_client.list_roots.return_value = mock_roots_response
    mock_orgs_client.describe_organizational_unit.return_value = mock_ou_response
    mock_orgs_client.describe_policy.return_value = mock_policy_details_response

    # Set up paginators with depth limit
    def get_paginator_side_effect(operation):
        if operation == "list_accounts_for_parent":
            return mock_accounts_paginator
        elif operation == "list_children":
            # Return empty children after first level to prevent recursion
            empty_paginator = MagicMock()
            empty_paginator.paginate.return_value = [{"Children": []}]
            return empty_paginator
        elif operation == "list_policies_for_target":
            return mock_policies_for_target_paginator
        return MagicMock()

    mock_orgs_client.get_paginator.side_effect = get_paginator_side_effect

    # Call the function
    org = fetch_organization(mock_session)

    # Verify the result
    assert isinstance(org, Organization)
    assert org.master_account_id == "123456789012"
    assert org.arn == (
        "arn:aws:organizations::123456789012:organization/o-exampleorgid"
    )
    assert org.feature_set == "ALL"
    assert isinstance(org.root, OrganizationalUnit)
    assert org.root.id == "r-examplerootid"
    assert org.root.name == "Root"

    # Verify SCPs are fetched
    assert len(org.root.scps) == 1
    assert isinstance(org.root.scps[0], ControlPolicy)
    assert org.root.scps[0].id == "p-examplepolicyid1"
    assert org.root.scps[0].name == "DenyAllPolicy"
    assert org.root.scps[0].description == "Denies all actions"
    assert org.root.scps[0].type == "SERVICE_CONTROL_POLICY"
    assert "Deny" in org.root.scps[0].content

    # Verify API calls
    mock_orgs_client.describe_organization.assert_called_once()
    mock_orgs_client.list_roots.assert_called_once()
    mock_orgs_client.get_paginator.assert_any_call("list_accounts_for_parent")
    mock_orgs_client.get_paginator.assert_any_call("list_children")
    mock_orgs_client.get_paginator.assert_any_call("list_policies_for_target")
    mock_orgs_client.describe_policy.assert_called_with(PolicyId="p-examplepolicyid1")


def test_fetch_organization_not_in_use(mock_session, mock_orgs_client):
    """Test when AWS Organizations is not in use."""

    # Set up mock to raise exception
    class MockException(Exception):
        def __init__(self):
            self.response = {"Error": {"Code": "AWSOrganizationsNotInUseException"}}

    mock_orgs_client.describe_organization.side_effect = MockException()

    # Call the function
    org = fetch_organization(mock_session)

    # Verify the result
    assert org is None


def test_fetch_organization_error(mock_session, mock_orgs_client):
    """Test when an error occurs."""
    # Set up mock to raise exception
    mock_orgs_client.describe_organization.side_effect = ClientError(
        dict(code="error", message="Test error"), "DescribeOrganization"
    )

    # Call the function and expect exception
    with pytest.raises(ClientError):
        fetch_organization(mock_session)


def test_build_ou_structure(
    mock_orgs_client,
    mock_ou_response,
    mock_accounts_paginator,
    mock_children_paginator,
    mock_policies_for_target_paginator,
    mock_policy_details_response,
):
    """Test building OU structure."""
    # Set up mocks
    mock_orgs_client.describe_organizational_unit.return_value = mock_ou_response
    mock_orgs_client.describe_policy.return_value = mock_policy_details_response

    # Set up paginators with depth limit
    def get_paginator_side_effect(operation):
        if operation == "list_accounts_for_parent":
            return mock_accounts_paginator
        elif operation == "list_children":
            # Return empty children after first level to prevent recursion
            empty_paginator = MagicMock()
            empty_paginator.paginate.return_value = [{"Children": []}]
            return empty_paginator
        elif operation == "list_policies_for_target":
            return mock_policies_for_target_paginator
        return MagicMock()

    mock_orgs_client.get_paginator.side_effect = get_paginator_side_effect

    # Call the function
    ou = build_ou_structure(mock_orgs_client, "ou-exampleouid1")

    # Verify the result
    assert isinstance(ou, OrganizationalUnit)
    assert ou.id == "ou-exampleouid1"
    assert ou.name == "OU 1"
    assert ou.arn == (
        "arn:aws:organizations::123456789012:ou/o-exampleorgid/ou-exampleouid1"
    )

    # Verify SCPs are fetched
    assert len(ou.scps) == 1
    assert isinstance(ou.scps[0], ControlPolicy)
    assert ou.scps[0].id == "p-examplepolicyid1"
    assert ou.scps[0].name == "DenyAllPolicy"

    # Verify API calls
    mock_orgs_client.describe_organizational_unit.assert_called_with(
        OrganizationalUnitId="ou-exampleouid1"
    )
    mock_orgs_client.get_paginator.assert_any_call("list_accounts_for_parent")
    mock_orgs_client.get_paginator.assert_any_call("list_children")
    mock_orgs_client.get_paginator.assert_any_call("list_policies_for_target")
    mock_orgs_client.describe_policy.assert_called_with(PolicyId="p-examplepolicyid1")


def test_fetch_delegated_admins_success(
    mock_session,
    mock_orgs_client,
    mock_delegated_admins_paginator,
    mock_delegated_services_paginator,
    mock_account_details_response,
):
    """Test fetching delegated admins successfully."""
    # Set up the mock client
    mock_orgs_client.get_paginator.side_effect = lambda operation: {
        "list_delegated_administrators": mock_delegated_admins_paginator,
        "list_delegated_services_for_account": mock_delegated_services_paginator,
    }[operation]
    mock_orgs_client.describe_account.return_value = mock_account_details_response

    # Call the function
    result = fetch_delegated_admins(mock_session)

    # Verify the result
    assert len(result) == 2
    admin = result[0]
    assert isinstance(admin, DelegatedAdmin)
    assert admin.id == "123456789012"
    assert admin.email == "security@example.com"
    assert admin.name == "Security Account"
    assert admin.status == "ACTIVE"
    assert admin.joined_method == "INVITED"
    assert admin.service_principal == "securityhub.amazonaws.com"

    # Verify the API calls
    mock_orgs_client.get_paginator.assert_any_call("list_delegated_administrators")
    mock_orgs_client.get_paginator.assert_any_call(
        "list_delegated_services_for_account"
    )
    mock_orgs_client.describe_account.assert_called_with(AccountId="123456789012")


def test_fetch_delegated_admins_not_in_use(mock_session, mock_orgs_client):
    """Test fetching delegated admins when Organizations is not in use."""

    # Set up the mock client to raise an exception
    class MockException(Exception):
        def __init__(self):
            self.response = {
                "Error": {
                    "Code": "AWSOrganizationsNotInUseException",
                    "Message": "AWS Organizations is not in use",
                }
            }

    mock_orgs_client.get_paginator.side_effect = MockException()

    # Call the function
    result = fetch_delegated_admins(mock_session)

    # Verify the result
    assert result == []


def test_fetch_delegated_admins_error(mock_session, mock_orgs_client):
    """Test fetching delegated admins when an error occurs."""
    # Set up the mock client to raise an exception
    mock_orgs_client.get_paginator.side_effect = Exception("Test error")

    # Call the function and expect it to raise the exception
    with pytest.raises(Exception) as excinfo:
        fetch_delegated_admins(mock_session)

    # Verify the exception
    assert "Test error" in str(excinfo.value)
