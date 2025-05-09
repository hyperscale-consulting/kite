import pytest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

from kite.identity_center import is_identity_center_used


@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = MagicMock()
    return session


@pytest.fixture
def mock_sso_admin_client(mocker):
    return mocker.Mock()


def test_is_identity_center_enabled_success(mock_session, mock_sso_admin_client):
    """Test successful check for Identity Center enabled."""
    # Set up the mock SSO Admin client
    mock_session.client.return_value = mock_sso_admin_client

    # Mock the list_instances response with an instance
    mock_sso_admin_client.list_instances.return_value = {
        "Instances": [
            {
                "InstanceArn": "arn:aws:sso:::instance/ssoins-12345678901234567",
                "IdentityStoreId": "d-1234567890",
                "Status": "ACTIVE",
            }
        ]
    }

    # Call the function
    result = is_identity_center_used(mock_session)

    # Verify the result
    assert result is True


def test_is_identity_center_enabled_no_instances(mock_session, mock_sso_admin_client):
    """Test when no Identity Center instances are found."""
    # Set up the mock SSO Admin client
    mock_session.client.return_value = mock_sso_admin_client

    # Mock the list_instances response with no instances
    mock_sso_admin_client.list_instances.return_value = {"Instances": []}

    # Call the function
    result = is_identity_center_used(mock_session)

    # Verify the result
    assert result is False


def test_is_identity_center_enabled_error(mock_session, mock_sso_admin_client):
    """Test error handling when checking Identity Center status."""
    # Set up the mock SSO Admin client
    mock_session.client.return_value = mock_sso_admin_client

    # Mock the list_instances to raise an error
    mock_sso_admin_client.list_instances.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "list_instances",
    )

    # Call the function and expect an exception
    with pytest.raises(ClientError):
        is_identity_center_used(mock_session)
