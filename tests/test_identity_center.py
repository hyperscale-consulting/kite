import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from kite.identity_center import is_identity_center_used, list_identity_center_instances


@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = MagicMock()
    return session


@pytest.fixture
def mock_sso_admin_client(mocker):
    return mocker.Mock()


def test_list_identity_center_instances_success(mock_session, mock_sso_admin_client):
    """Test successful listing of Identity Center instances."""
    # Set up the mock SSO Admin client
    mock_session.client.return_value = mock_sso_admin_client

    # Mock the paginator and its pages
    mock_paginator = MagicMock()
    mock_sso_admin_client.get_paginator.return_value = mock_paginator

    # Mock two pages of results
    mock_paginator.paginate.return_value = [
        {
            "Instances": [
                {
                    "InstanceArn": "arn:aws:sso:::instance/ssoins-12345678901234567",
                    "IdentityStoreId": "d-1234567890",
                    "Status": "ACTIVE",
                }
            ]
        },
        {
            "Instances": [
                {
                    "InstanceArn": "arn:aws:sso:::instance/ssoins-76543210987654321",
                    "IdentityStoreId": "d-0987654321",
                    "Status": "ACTIVE",
                }
            ]
        }
    ]

    # Call the function
    result = list_identity_center_instances(mock_session)

    # Verify the result
    assert len(result) == 2
    assert result[0]["InstanceArn"] == "arn:aws:sso:::instance/ssoins-12345678901234567"
    assert result[1]["InstanceArn"] == "arn:aws:sso:::instance/ssoins-76543210987654321"


def test_list_identity_center_instances_empty(mock_session, mock_sso_admin_client):
    """Test when no Identity Center instances are found."""
    # Set up the mock SSO Admin client
    mock_session.client.return_value = mock_sso_admin_client

    # Mock the paginator with empty results
    mock_paginator = MagicMock()
    mock_sso_admin_client.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [{"Instances": []}]

    # Call the function
    result = list_identity_center_instances(mock_session)

    # Verify the result
    assert len(result) == 0


def test_list_identity_center_instances_error(mock_session, mock_sso_admin_client):
    """Test error handling when listing Identity Center instances."""
    # Set up the mock SSO Admin client
    mock_session.client.return_value = mock_sso_admin_client

    # Mock the paginator to raise an error
    mock_paginator = MagicMock()
    mock_sso_admin_client.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "list_instances",
    )

    # Call the function and expect an exception
    with pytest.raises(ClientError):
        list_identity_center_instances(mock_session)


def test_is_identity_center_enabled_success(mock_session, mock_sso_admin_client):
    """Test successful check for Identity Center enabled."""
    # Set up the mock SSO Admin client
    mock_session.client.return_value = mock_sso_admin_client

    # Mock the paginator and its pages
    mock_paginator = MagicMock()
    mock_sso_admin_client.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {
            "Instances": [
                {
                    "InstanceArn": "arn:aws:sso:::instance/ssoins-12345678901234567",
                    "IdentityStoreId": "d-1234567890",
                    "Status": "ACTIVE",
                }
            ]
        }
    ]

    # Call the function
    result = is_identity_center_used(mock_session)

    # Verify the result
    assert result is True


def test_is_identity_center_enabled_no_instances(mock_session, mock_sso_admin_client):
    """Test when no Identity Center instances are found."""
    # Set up the mock SSO Admin client
    mock_session.client.return_value = mock_sso_admin_client

    # Mock the paginator with empty results
    mock_paginator = MagicMock()
    mock_sso_admin_client.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [{"Instances": []}]

    # Call the function
    result = is_identity_center_used(mock_session)

    # Verify the result
    assert result is False


def test_is_identity_center_enabled_error(mock_session, mock_sso_admin_client):
    """Test error handling when checking Identity Center status."""
    # Set up the mock SSO Admin client
    mock_session.client.return_value = mock_sso_admin_client

    # Mock the paginator to raise an error
    mock_paginator = MagicMock()
    mock_sso_admin_client.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "list_instances",
    )

    # Call the function and expect an exception
    with pytest.raises(ClientError):
        is_identity_center_used(mock_session)
