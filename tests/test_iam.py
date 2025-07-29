"""Tests for IAM module."""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from hyperscale.kite.iam import fetch_credentials_report
from hyperscale.kite.iam import fetch_virtual_mfa_devices
from hyperscale.kite.iam import list_oidc_providers
from hyperscale.kite.iam import list_saml_providers


def _get_csv_header():
    """Get the CSV header for credentials report."""
    return (
        "user,arn,user_creation_time,password_enabled,password_last_used,"
        "password_last_changed,password_next_rotation,mfa_enabled,"
        "access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
        "access_key_1_last_used_region,access_key_1_last_used_service,"
        "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
        "access_key_2_last_used_region,access_key_2_last_used_service,"
        "cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated"
    )


def _get_root_account_csv():
    """Get the root account CSV line."""
    return (
        "<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,"
        "true,2023-01-01T00:00:00+00:00,2020-01-01T00:00:00+00:00,N/A,false,"
        "false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"
    )


def _get_user_csv():
    """Get a sample user CSV line."""
    return (
        "user1,arn:aws:iam::123456789012:user/user1,2021-01-01T00:00:00+00:00,"
        "true,2022-01-01T00:00:00+00:00,2021-01-01T00:00:00+00:00,"
        "2023-01-01T00:00:00+00:00,true,true,2021-01-01T00:00:00+00:00,"
        "2022-01-01T00:00:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A,"
        "false,N/A,false,N/A"
    )


def _create_credentials_report(include_root=True, include_user=False):
    """Create a credentials report with specified accounts."""
    lines = [_get_csv_header()]
    if include_root:
        lines.append(_get_root_account_csv())
    if include_user:
        lines.append(_get_user_csv())
    return {"Content": "\n".join(lines).encode("utf-8")}


@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = MagicMock()
    iam_client = MagicMock()
    session.client.return_value = iam_client
    return session


@pytest.fixture
def mock_iam_client():
    """Create a mock IAM client."""
    client = MagicMock()
    return client


def test_fetch_credentials_report_success(mock_session, mock_iam_client):
    """Test successful fetch of credentials report."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the generate_credential_report response
    mock_iam_client.generate_credential_report.return_value = {}

    # Mock the get_credential_report response with sample data
    mock_iam_client.get_credential_report.return_value = _create_credentials_report(
        include_root=True, include_user=True
    )

    # Call the function
    result = fetch_credentials_report(mock_session)

    # Verify the result structure
    assert "root" in result
    assert "users" in result
    assert len(result["users"]) == 1

    # Verify root account details
    root = result["root"]
    assert root["user"] == "<root_account>"
    assert root["password_enabled"] == "true"
    assert root["password_last_used"] == "2023-01-01T00:00:00+00:00"
    assert root["mfa_enabled"] == "false"
    assert root["access_key_1_active"] == "false"
    assert root["access_key_2_active"] == "false"

    # Verify user1 details
    user1 = result["users"][0]
    assert user1["user"] == "user1"
    assert user1["password_enabled"] == "true"
    assert user1["password_last_used"] == "2022-01-01T00:00:00+00:00"
    assert user1["mfa_enabled"] == "true"
    assert user1["access_key_1_active"] == "true"
    assert user1["access_key_2_active"] == "false"

    # Verify the IAM client was called correctly
    mock_iam_client.generate_credential_report.assert_called_once()
    mock_iam_client.get_credential_report.assert_called_once()


def test_fetch_credentials_report_report_in_progress(mock_session, mock_iam_client):
    """Test handling of ReportInProgress error with retry."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock generate_credential_report to return ReportInProgress first
    mock_iam_client.generate_credential_report.side_effect = [
        ClientError(
            {"Error": {"Code": "ReportInProgress", "Message": "Report in progress"}},
            "generate_credential_report",
        ),
        {},
    ]

    # Mock the get_credential_report response
    mock_iam_client.get_credential_report.return_value = _create_credentials_report(
        include_root=True
    )

    # Call the function
    result = fetch_credentials_report(mock_session)

    # Verify the result
    assert "root" in result
    assert "users" in result
    assert len(result["users"]) == 0

    # Verify the IAM client was called correctly
    assert mock_iam_client.generate_credential_report.call_count == 1
    mock_iam_client.get_credential_report.assert_called_once()


def test_fetch_report_in_progress_error(mock_session, mock_iam_client):
    """Test handling of ReportInProgress error with ClientError."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock generate_credential_report to raise ClientError
    error_response = {
        "Error": {
            "Code": "ReportInProgress",
            "Message": "Credential report generation is already in progress",
        }
    }
    mock_iam_client.generate_credential_report.side_effect = ClientError(
        error_response, "generate_credential_report"
    )

    # Mock the get_credential_report response
    mock_iam_client.get_credential_report.return_value = _create_credentials_report(
        include_root=True
    )

    # Call the function
    result = fetch_credentials_report(mock_session)

    # Verify the result
    assert "root" in result
    assert "users" in result
    assert len(result["users"]) == 0

    # Verify the IAM client was called correctly
    assert mock_iam_client.generate_credential_report.call_count == 1
    mock_iam_client.get_credential_report.assert_called_once()


def test_fetch_credentials_report_other_error(mock_session, mock_iam_client):
    """Test handling of other errors."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock generate_credential_report to raise a different ClientError
    error_response = {
        "Error": {
            "Code": "AccessDenied",
            "Message": (
                "User is not authorized to perform: iam:GenerateCredentialReport"
            ),
        }
    }
    mock_iam_client.generate_credential_report.side_effect = ClientError(
        error_response, "generate_credential_report"
    )

    # Call the function and expect it to raise the exception
    with pytest.raises(ClientError) as excinfo:
        fetch_credentials_report(mock_session)

    # Verify the error
    assert excinfo.value.response["Error"]["Code"] == "AccessDenied"


def test_fetch_credentials_report_no_root_account(mock_session, mock_iam_client):
    """Test handling of report with no root account."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the generate_credential_report response
    mock_iam_client.generate_credential_report.return_value = {}

    # Mock the get_credential_report response with no root account
    mock_iam_client.get_credential_report.return_value = _create_credentials_report(
        include_root=False, include_user=True
    )

    # Call the function
    result = fetch_credentials_report(mock_session)

    # Verify the result
    assert result["root"] is None
    assert "users" in result
    assert len(result["users"]) == 1

    # Verify the IAM client was called correctly
    mock_iam_client.generate_credential_report.assert_called_once()
    mock_iam_client.get_credential_report.assert_called_once()


def test_fetch_credentials_report_empty_report(mock_session, mock_iam_client):
    """Test handling of empty report."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the generate_credential_report response
    mock_iam_client.generate_credential_report.return_value = {}

    # Mock the get_credential_report response with empty report
    mock_iam_client.get_credential_report.return_value = _create_credentials_report(
        include_root=False, include_user=False
    )

    # Call the function
    result = fetch_credentials_report(mock_session)

    # Verify the result
    assert result["root"] is None
    assert "users" in result
    assert len(result["users"]) == 0

    # Verify the IAM client was called correctly
    mock_iam_client.generate_credential_report.assert_called_once()
    mock_iam_client.get_credential_report.assert_called_once()


def test_fetch_organization_features_success(mock_session, mock_iam_client):
    """Test successful fetch of organization features."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the list_organizations_features response
    mock_iam_client.list_organizations_features.return_value = {
        "EnabledFeatures": ["RootCredentialsManagement"]
    }

    # Call the function
    from hyperscale.kite.iam import fetch_organization_features

    result = fetch_organization_features(mock_session)

    # Verify the result
    assert "RootCredentialsManagement" in result
    assert len(result) == 1

    # Verify the IAM client was called correctly
    mock_iam_client.list_organizations_features.assert_called_once()


def test_fetch_organization_features_no_features(mock_session, mock_iam_client):
    """Test fetch of organization features when none are enabled."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the list_organizations_features response with no features
    mock_iam_client.list_organizations_features.return_value = {"EnabledFeatures": []}

    # Call the function
    from hyperscale.kite.iam import fetch_organization_features

    result = fetch_organization_features(mock_session)

    # Verify the result is an empty list
    assert result == []

    # Verify the IAM client was called correctly
    mock_iam_client.list_organizations_features.assert_called_once()


def test_fetch_organization_features_no_organizations(mock_session, mock_iam_client):
    """Test fetch of organization features when Organizations is not in use."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the list_organizations_features to raise NoSuchEntity error
    error_response = {
        "Error": {"Code": "NoSuchEntity", "Message": "Organizations is not in use"}
    }
    mock_iam_client.list_organizations_features.side_effect = ClientError(
        error_response, "list_organizations_features"
    )

    # Call the function
    from hyperscale.kite.iam import fetch_organization_features

    result = fetch_organization_features(mock_session)

    # Verify the result is an empty list
    assert result == []

    # Verify the IAM client was called correctly
    mock_iam_client.list_organizations_features.assert_called_once()


def test_fetch_organization_features_other_error(mock_session, mock_iam_client):
    """Test handling of other errors when fetching organization features."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock list_organizations_features to raise a different ClientError
    error_response = {
        "Error": {
            "Code": "AccessDenied",
            "Message": (
                "User is not authorized to perform: "
                "organizations:ListOrganizationsFeatures"
            ),
        }
    }
    mock_iam_client.list_organizations_features.side_effect = ClientError(
        error_response, "list_organizations_features"
    )

    # Call the function and expect it to raise the exception
    from hyperscale.kite.iam import fetch_organization_features

    with pytest.raises(ClientError) as excinfo:
        fetch_organization_features(mock_session)

    # Verify the error
    assert excinfo.value.response["Error"]["Code"] == "AccessDenied"


def test_fetch_account_summary_success(mock_session, mock_iam_client):
    """Test successful fetch of account summary."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the get_account_summary response
    mock_iam_client.get_account_summary.return_value = {
        "SummaryMap": {
            "Users": 0,
            "Groups": 0,
            "Roles": 55,
            "Policies": 44,
            "AccountMFAEnabled": 1,
            "AccountPasswordPresent": 1,
            "AccountAccessKeysPresent": 0,
            "MFADevices": 1,
            "MFADevicesInUse": 1,
            "UsersQuota": 5000,
            "GroupsQuota": 300,
            "RolesQuota": 1000,
            "PoliciesQuota": 1500,
        }
    }

    # Call the function
    from hyperscale.kite.iam import fetch_account_summary

    result = fetch_account_summary(mock_session)

    # Verify the result
    assert result["Users"] == 0
    assert result["Groups"] == 0
    assert result["Roles"] == 55
    assert result["Policies"] == 44
    assert result["AccountMFAEnabled"] == 1
    assert result["AccountPasswordPresent"] == 1
    assert result["AccountAccessKeysPresent"] == 0
    assert result["MFADevices"] == 1
    assert result["MFADevicesInUse"] == 1
    assert result["UsersQuota"] == 5000
    assert result["GroupsQuota"] == 300
    assert result["RolesQuota"] == 1000
    assert result["PoliciesQuota"] == 1500

    # Verify the IAM client was called correctly
    mock_iam_client.get_account_summary.assert_called_once()


def test_fetch_account_summary_error(mock_session, mock_iam_client):
    """Test error handling when fetching account summary."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock get_account_summary to raise a ClientError
    error_response = {
        "Error": {
            "Code": "AccessDenied",
            "Message": "User is not authorized to perform: iam:GetAccountSummary",
        }
    }
    mock_iam_client.get_account_summary.side_effect = ClientError(
        error_response, "get_account_summary"
    )

    # Call the function and expect it to raise the exception
    from hyperscale.kite.iam import fetch_account_summary

    with pytest.raises(ClientError) as excinfo:
        fetch_account_summary(mock_session)

    # Verify the error
    assert excinfo.value.response["Error"]["Code"] == "AccessDenied"


def test_fetch_virtual_mfa_devices(mock_session, mock_iam_client):
    """Test successful fetch of root virtual MFA device."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Create a mock paginator
    mock_paginator = MagicMock()
    mock_iam_client.get_paginator.return_value = mock_paginator

    # Mock the paginate response
    mock_paginator.paginate.return_value = [
        {
            "VirtualMFADevices": [
                {
                    "SerialNumber": "arn:aws:iam::123456789012:mfa/root",
                    "User": {"Arn": "arn:aws:iam::123456789012:root"},
                },
                {
                    "SerialNumber": "arn:aws:iam::123456789012:mfa/user1",
                    "User": {"Arn": "arn:aws:iam::123456789012:user/user1"},
                },
            ]
        }
    ]

    # Call the function
    result = fetch_virtual_mfa_devices(mock_session)

    # Verify the result
    assert result == [
        {
            "SerialNumber": "arn:aws:iam::123456789012:mfa/root",
            "User": {"Arn": "arn:aws:iam::123456789012:root"},
        },
        {
            "SerialNumber": "arn:aws:iam::123456789012:mfa/user1",
            "User": {"Arn": "arn:aws:iam::123456789012:user/user1"},
        },
    ]

    # Verify the paginator was used correctly
    mock_iam_client.get_paginator.assert_called_once_with("list_virtual_mfa_devices")
    mock_paginator.paginate.assert_called_once()


def test_list_saml_providers_success(mock_session, mock_iam_client):
    """Test successful listing of SAML providers."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the list_saml_providers response
    mock_iam_client.list_saml_providers.return_value = {
        "SAMLProviderList": [
            {
                "Arn": "arn:aws:iam::123456789012:saml-provider/MySAMLProvider",
                "ValidUntil": "2024-01-01T00:00:00Z",
                "CreateDate": "2023-01-01T00:00:00Z",
            }
        ]
    }

    # Call the function
    result = list_saml_providers(mock_session)

    # Verify the result
    assert len(result) == 1
    assert result[0]["Arn"] == "arn:aws:iam::123456789012:saml-provider/MySAMLProvider"
    assert result[0]["ValidUntil"] == "2024-01-01T00:00:00Z"
    assert result[0]["CreateDate"] == "2023-01-01T00:00:00Z"

    # Verify the client was used correctly
    mock_iam_client.list_saml_providers.assert_called_once()


def test_list_saml_providers_error(mock_session, mock_iam_client):
    """Test error handling when listing SAML providers."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the list_saml_providers to raise an error
    mock_iam_client.list_saml_providers.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "list_saml_providers",
    )

    # Call the function and expect an exception
    with pytest.raises(ClientError):
        list_saml_providers(mock_session)

    # Verify the client was used correctly
    mock_iam_client.list_saml_providers.assert_called_once()


def test_list_oidc_providers_success(mock_session, mock_iam_client):
    """Test successful listing of OIDC providers."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the list_open_id_connect_providers response
    mock_iam_client.list_open_id_connect_providers.return_value = {
        "OpenIDConnectProviderList": [
            {
                "Arn": "arn:aws:iam::123456789012:oidc-provider/MyOIDCProvider",
                "CreateDate": "2023-01-01T00:00:00Z",
            }
        ]
    }

    # Mock the get_open_id_connect_provider response
    mock_iam_client.get_open_id_connect_provider.return_value = {
        "Url": "https://example.com",
        "ClientIDList": ["client1", "client2"],
        "ThumbprintList": ["thumbprint1", "thumbprint2"],
    }

    # Call the function
    result = list_oidc_providers(mock_session)

    # Verify the result
    assert len(result) == 1
    assert result[0]["Arn"] == "arn:aws:iam::123456789012:oidc-provider/MyOIDCProvider"
    assert result[0]["CreateDate"] == "2023-01-01T00:00:00Z"
    assert result[0]["Url"] == "https://example.com"
    assert result[0]["ClientIDList"] == ["client1", "client2"]
    assert result[0]["ThumbprintList"] == ["thumbprint1", "thumbprint2"]

    # Verify the client was used correctly
    mock_iam_client.list_open_id_connect_providers.assert_called_once()
    mock_iam_client.get_open_id_connect_provider.assert_called_once_with(
        OpenIDConnectProviderArn="arn:aws:iam::123456789012:oidc-provider/MyOIDCProvider"
    )


def test_list_oidc_providers_error(mock_session, mock_iam_client):
    """Test error handling when listing OIDC providers."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the list_open_id_connect_providers to raise an error
    mock_iam_client.list_open_id_connect_providers.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "list_open_id_connect_providers",
    )

    # Call the function and expect an exception
    with pytest.raises(ClientError):
        list_oidc_providers(mock_session)

    # Verify the client was used correctly
    mock_iam_client.list_open_id_connect_providers.assert_called_once()


def test_list_oidc_providers_get_provider_error(mock_session, mock_iam_client):
    """Test error handling when getting OIDC provider details."""
    # Set up the mock IAM client
    mock_session.client.return_value = mock_iam_client

    # Mock the list_open_id_connect_providers response
    mock_iam_client.list_open_id_connect_providers.return_value = {
        "OpenIDConnectProviderList": [
            {
                "Arn": "arn:aws:iam::123456789012:oidc-provider/MyOIDCProvider",
                "CreateDate": "2023-01-01T00:00:00Z",
            }
        ]
    }

    # Mock the get_open_id_connect_provider to raise an error
    mock_iam_client.get_open_id_connect_provider.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "get_open_id_connect_provider",
    )

    # Call the function
    result = list_oidc_providers(mock_session)

    # Verify the result contains basic info even when detailed info fails
    assert len(result) == 1
    assert result[0]["Arn"] == "arn:aws:iam::123456789012:oidc-provider/MyOIDCProvider"
    assert result[0]["CreateDate"] == "2023-01-01T00:00:00Z"
    assert "Url" not in result[0]
    assert "ClientIDList" not in result[0]
    assert "ThumbprintList" not in result[0]

    # Verify the client was used correctly
    mock_iam_client.list_open_id_connect_providers.assert_called_once()
    mock_iam_client.get_open_id_connect_provider.assert_called_once_with(
        OpenIDConnectProviderArn="arn:aws:iam::123456789012:oidc-provider/MyOIDCProvider"
    )
