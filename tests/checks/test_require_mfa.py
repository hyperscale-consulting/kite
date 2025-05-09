import pytest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError

from kite.checks.require_mfa.check import check_require_mfa


@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = MagicMock()
    return session


@pytest.fixture
def mock_get_credentials_report(mocker):
    return mocker.patch("kite.checks.require_mfa.check.get_credentials_report")


@pytest.fixture
def mock_get_account_ids_in_scope(mocker):
    return mocker.patch("kite.checks.require_mfa.check.get_account_ids_in_scope")


@pytest.fixture
def mock_get_saml_providers(mocker):
    return mocker.patch("kite.checks.require_mfa.check.get_saml_providers")


@pytest.fixture
def mock_get_oidc_providers(mocker):
    return mocker.patch("kite.checks.require_mfa.check.get_oidc_providers")


@pytest.fixture
def mock_is_identity_center_enabled(mocker):
    return mocker.patch("kite.checks.require_mfa.check.is_identity_center_enabled")


@pytest.fixture
def mock_manual_check(mocker):
    return mocker.patch("kite.checks.require_mfa.check.manual_check")


@pytest.fixture
def mock_iam_client():
    """Create a mock IAM client."""
    client = MagicMock()
    return client


@pytest.fixture
def mock_sso_admin_client():
    """Create a mock SSO Admin client."""
    client = MagicMock()
    return client


@pytest.fixture
def mock_sts_client():
    """Create a mock STS client."""
    client = MagicMock()
    return client


@pytest.fixture
def mock_boto3_client(mock_iam_client, mock_sso_admin_client, mock_sts_client):
    """Mock boto3.client to prevent SSO token errors."""
    with patch("boto3.client") as mock_client:
        mock_client.side_effect = lambda service, **kwargs: {
            "iam": mock_iam_client,
            "sso-admin": mock_sso_admin_client,
            "sts": mock_sts_client,
        }[service]
        yield mock_client


@pytest.fixture
def mock_boto3_session(mock_boto3_client):
    """Mock boto3.Session to prevent SSO token errors."""
    with patch("boto3.Session") as mock_session:
        mock_session.return_value.client = mock_boto3_client
        yield mock_session


def test_check_require_mfa_success(
    mock_session,
    mock_get_credentials_report,
    mock_get_account_ids_in_scope,
    mock_get_saml_providers,
    mock_get_oidc_providers,
    mock_is_identity_center_enabled,
    mock_manual_check,
    mock_boto3_client,
    mock_boto3_session,
    mock_sts_client,
):
    """Test successful check with no users without MFA."""
    # Mock STS assume role response
    mock_sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "test",
            "SecretAccessKey": "test",
            "SessionToken": "test",
            "Expiration": "2024-01-01 00:00:00",
        }
    }

    # Mock account IDs
    mock_get_account_ids_in_scope.return_value = ["123456789012"]

    # Mock credentials report with all users having MFA
    mock_get_credentials_report.return_value = {
        "users": [
            {
                "user": "user1",
                "mfa_active": "true",
                "password_enabled": "true",
                "access_key_1_active": "false",
                "access_key_2_active": "false",
            }
        ]
    }

    # Mock SAML providers
    mock_get_saml_providers.return_value = [
        {
            "Arn": "arn:aws:iam::123456789012:saml-provider/MySAMLProvider",
            "ValidUntil": "2024-01-01T00:00:00Z",
            "CreateDate": "2023-01-01T00:00:00Z",
        }
    ]

    # Mock OIDC providers
    mock_get_oidc_providers.return_value = [
        {
            "Arn": "arn:aws:iam::123456789012:oidc-provider/MyOIDCProvider",
            "CreateDate": "2023-01-01T00:00:00Z",
            "Url": "https://example.com",
            "ClientIDList": ["client1"],
            "ThumbprintList": ["thumbprint1"],
        }
    ]

    # Mock Identity Center status
    mock_is_identity_center_enabled.return_value = True

    # Mock manual check response
    mock_manual_check.return_value = {
        "check_id": "require-mfa",
        "check_name": "Require MFA",
        "passed": True,
        "message": "MFA is required for AWS access",
    }

    # Run the check
    result = check_require_mfa()

    # Verify the result
    assert result["passed"] is True
    assert "MFA is required for AWS access" in result["message"]


def test_check_require_mfa_users_without_mfa(
    mock_session,
    mock_get_credentials_report,
    mock_get_account_ids_in_scope,
    mock_get_saml_providers,
    mock_get_oidc_providers,
    mock_is_identity_center_enabled,
    mock_manual_check,
    mock_boto3_client,
    mock_boto3_session,
    mock_sts_client,
):
    """Test check with users without MFA."""
    # Mock STS assume role response
    mock_sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "test",
            "SecretAccessKey": "test",
            "SessionToken": "test",
            "Expiration": "2024-01-01 00:00:00",
        }
    }

    # Mock account IDs
    mock_get_account_ids_in_scope.return_value = ["123456789012"]

    # Mock credentials report with users missing MFA
    mock_get_credentials_report.return_value = {
        "users": [
            {
                "user": "user1",
                "mfa_active": "false",
                "password_enabled": "true",
                "access_key_1_active": "true",
                "access_key_2_active": "false",
            },
            {
                "user": "user2",
                "mfa_active": "true",
                "password_enabled": "true",
                "access_key_1_active": "false",
                "access_key_2_active": "false",
            },
        ]
    }

    # Mock empty SAML and OIDC providers
    mock_get_saml_providers.return_value = []
    mock_get_oidc_providers.return_value = []

    # Mock Identity Center status
    mock_is_identity_center_enabled.return_value = False

    # Mock manual check response
    mock_manual_check.return_value = {
        "check_id": "require-mfa",
        "check_name": "Require MFA",
        "passed": False,
        "message": "MFA is not required for AWS access",
    }

    # Run the check
    result = check_require_mfa()

    # Verify the result
    assert result["passed"] is False
    assert "MFA is not required for AWS access" in result["message"]


def test_check_require_mfa_credentials_report_error(
    mock_session,
    mock_get_credentials_report,
    mock_get_account_ids_in_scope,
    mock_get_saml_providers,
    mock_get_oidc_providers,
    mock_is_identity_center_enabled,
    mock_manual_check,
    mock_boto3_client,
    mock_boto3_session,
    mock_sts_client,
):
    """Test check when credentials report fails."""
    # Mock STS assume role response
    mock_sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "test",
            "SecretAccessKey": "test",
            "SessionToken": "test",
            "Expiration": "2024-01-01 00:00:00",
        }
    }

    # Mock account IDs
    mock_get_account_ids_in_scope.return_value = ["123456789012"]

    # Mock credentials report error
    mock_get_credentials_report.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "get_credentials_report",
    )

    # Mock empty SAML and OIDC providers
    mock_get_saml_providers.return_value = []
    mock_get_oidc_providers.return_value = []

    # Mock Identity Center status
    mock_is_identity_center_enabled.return_value = False

    # Mock manual check response
    mock_manual_check.return_value = {
        "check_id": "require-mfa",
        "check_name": "Require MFA",
        "passed": False,
        "message": "Failed to retrieve credentials report",
    }

    # Run the check
    result = check_require_mfa()

    # Verify the result
    assert result["passed"] is False
    assert "Failed to retrieve credentials report" in result["message"]


def test_check_require_mfa_provider_error(
    mock_session,
    mock_get_credentials_report,
    mock_get_account_ids_in_scope,
    mock_get_saml_providers,
    mock_get_oidc_providers,
    mock_is_identity_center_enabled,
    mock_manual_check,
    mock_boto3_client,
    mock_boto3_session,
    mock_sts_client,
):
    """Test check when provider listing fails."""
    # Mock STS assume role response
    mock_sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "test",
            "SecretAccessKey": "test",
            "SessionToken": "test",
            "Expiration": "2024-01-01 00:00:00",
        }
    }

    # Mock account IDs
    mock_get_account_ids_in_scope.return_value = ["123456789012"]

    # Mock credentials report with all users having MFA
    mock_get_credentials_report.return_value = {
        "users": [
            {
                "user": "user1",
                "mfa_active": "true",
                "password_enabled": "true",
                "access_key_1_active": "false",
                "access_key_2_active": "false",
            }
        ]
    }

    # Mock provider errors
    mock_get_saml_providers.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "list_saml_providers",
    )
    mock_get_oidc_providers.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "list_open_id_connect_providers",
    )

    # Mock Identity Center status
    mock_is_identity_center_enabled.return_value = False

    # Run the check
    result = check_require_mfa()

    # Verify the result
    assert result["check_id"] == "require-mfa"
    assert result["check_name"] == "Require MFA"
    assert result["status"] == "ERROR"
    assert "Error checking SAML providers" in result["details"]["message"]
    assert "Error checking OIDC providers" in result["details"]["message"]


def test_check_require_mfa_identity_center_error(
    mock_session,
    mock_get_credentials_report,
    mock_get_account_ids_in_scope,
    mock_get_saml_providers,
    mock_get_oidc_providers,
    mock_is_identity_center_enabled,
    mock_manual_check,
    mock_boto3_client,
    mock_boto3_session,
    mock_sts_client,
):
    """Test check when Identity Center check fails."""
    # Mock STS assume role response
    mock_sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "test",
            "SecretAccessKey": "test",
            "SessionToken": "test",
            "Expiration": "2024-01-01 00:00:00",
        }
    }

    # Mock account IDs
    mock_get_account_ids_in_scope.return_value = ["123456789012"]

    # Mock credentials report with all users having MFA
    mock_get_credentials_report.return_value = {
        "users": [
            {
                "user": "user1",
                "mfa_active": "true",
                "password_enabled": "true",
                "access_key_1_active": "false",
                "access_key_2_active": "false",
            }
        ]
    }

    # Mock successful provider checks
    mock_get_saml_providers.return_value = []
    mock_get_oidc_providers.return_value = []

    # Mock Identity Center error
    mock_is_identity_center_enabled.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
        "list_instances",
    )

    # Run the check
    result = check_require_mfa()

    # Verify the result
    assert result["check_id"] == "require-mfa"
    assert result["check_name"] == "Require MFA"
    assert result["status"] == "ERROR"
    assert "Error checking Identity Center status" in result["details"]["message"]
