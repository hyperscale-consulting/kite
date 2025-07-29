"""Tests for helper functions."""

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from hyperscale.kite.config import Config
from hyperscale.kite.helpers import get_account_ids_in_scope
from hyperscale.kite.helpers import get_organization_structure_str
from hyperscale.kite.organizations import Account
from hyperscale.kite.organizations import ControlPolicy
from hyperscale.kite.organizations import Organization
from hyperscale.kite.organizations import OrganizationalUnit


@pytest.fixture
def mock_session():
    """Create a mock boto3 session."""
    session = MagicMock()
    return session


@pytest.fixture
def mock_iam_client():
    """Create a mock IAM client."""
    client = MagicMock()
    return client


@pytest.fixture
def mock_organizations_client():
    """Create a mock Organizations client."""
    client = MagicMock()
    return client


@pytest.fixture
def mock_sts_client():
    """Create a mock STS client."""
    client = MagicMock()
    return client


@pytest.fixture
def mock_boto3_client():
    """Mock boto3.client to prevent SSO token errors."""
    with patch("boto3.client") as mock_client:
        yield mock_client


@pytest.fixture
def mock_boto3_session():
    """Mock boto3.Session to prevent SSO token errors."""
    with patch("boto3.Session") as mock_session:
        yield mock_session


@pytest.fixture
def mock_scp():
    """Create a mock SCP."""
    return ControlPolicy(
        id="p-1234",
        arn="arn:aws:organizations::123456789012:policy/o-abcd/p-1234",
        name="TestPolicy",
        description="Test policy description",
        content='{"Version":"2012-10-17"}',
        type="SERVICE_CONTROL_POLICY",
    )


@pytest.fixture
def mock_account(mock_scp):
    """Create a mock account."""
    return Account(
        id="123456789012",
        arn="arn:aws:organizations::123456789012:account/o-abcd/123456789012",
        name="Test Account",
        email="test@example.com",
        status="ACTIVE",
        joined_method="CREATED",
        joined_timestamp="2023-01-01T00:00:00Z",
        scps=[mock_scp],
    )


@pytest.fixture
def mock_child_ou(mock_scp, mock_account):
    """Create a mock child OU."""
    return OrganizationalUnit(
        id="ou-child",
        arn="arn:aws:organizations::123456789012:ou/o-abcd/ou-child",
        name="Child OU",
        accounts=[mock_account],
        child_ous=[],
        scps=[mock_scp],
    )


@pytest.fixture
def mock_root_ou(mock_scp, mock_child_ou):
    """Create a mock root OU."""
    return OrganizationalUnit(
        id="r-root",
        arn="arn:aws:organizations::123456789012:root/o-abcd/r-root",
        name="Root",
        accounts=[],
        child_ous=[mock_child_ou],
        scps=[mock_scp],
    )


@pytest.fixture
def mock_organization(mock_root_ou):
    """Create a mock organization."""
    return Organization(
        id="o-123456789012",
        master_account_id="123456789012",
        arn="arn:aws:organizations::123456789012:organization/o-123456789012",
        feature_set="ALL",
        root=mock_root_ou,
    )


@pytest.fixture
def mock_config():
    """Create a mock config."""
    config = MagicMock(spec=Config)
    config.management_account_id = "123456789012"
    config.account_ids = ["234567890123", "345678901234"]
    config.role_name = "OrganizationAccountAccessRole"
    return config


@pytest.fixture
def mock_config_instance(mock_config):
    """Mock the Config singleton instance."""
    with patch("hyperscale.kite.config.Config._instance", mock_config):
        yield mock_config


def test_get_organization_structure_str(
    organization, root_ou, security_ou, workload_account, full_access_scp
):
    """Test getting organization structure as a string."""
    result = get_organization_structure_str(organization)

    # Verify the structure contains all the expected elements
    assert f"Root: Root ({root_ou.id}) [SCPs: {full_access_scp.name}]" in result
    assert (
        f"OU: {security_ou.name} ({security_ou.id}) [SCPs: {full_access_scp.name}]"
        in result
    )
    assert (
        f"Account: {workload_account.name} ({workload_account.id})"
        f" [SCPs: {full_access_scp.name}]" in result
    )


def test_get_account_ids_in_scope_with_management_and_account_ids(mock_config):
    """Test get_account_ids_in_scope with management account and account IDs."""
    with patch("hyperscale.kite.helpers.Config.get", return_value=mock_config):
        account_ids = get_account_ids_in_scope()

        # Should include management account and account IDs
        assert "123456789012" in account_ids
        assert "234567890123" in account_ids
        assert "345678901234" in account_ids
        assert len(account_ids) == 3


def test_get_account_ids_in_scope_with_only_management_account(
    config,
    organization,
    audit_account_id,
    log_account_id,
    workload_account_id,
    mgmt_account_id,
):
    """Test get_account_ids_in_scope with only management account."""
    config.management_account_id = mgmt_account_id
    account_ids = get_account_ids_in_scope()

    expected_accounts = [
        audit_account_id,
        log_account_id,
        workload_account_id,
        mgmt_account_id,
    ]
    assert sorted(account_ids) == sorted(expected_accounts)


def test_get_account_ids_in_scope_with_only_account_ids(config, workload_account_id):
    """Test get_account_ids_in_scope with only account IDs."""
    # Create a config with only account IDs
    config.management_account_id = None
    config.account_ids = [workload_account_id]

    account_ids = get_account_ids_in_scope()

    # Should include only account IDs
    expected_accounts = [workload_account_id]
    assert sorted(account_ids) == sorted(expected_accounts)


def test_get_account_ids_in_scope_with_no_accounts(config):
    """Test get_account_ids_in_scope with no accounts."""
    config.management_account_id = None
    config.account_ids = []

    with pytest.raises(Exception) as excinfo:
        get_account_ids_in_scope()

    assert "No account IDs in scope" in str(excinfo.value)


def test_get_account_ids_in_scope_normalizes_account_ids(
    config, organization, workload_account_id, log_account_id, mgmt_account_id
):
    """Test get_account_ids_in_scope normalizes account IDs to strings."""
    # Create a config with mixed account ID types
    config.management_account_id = int(mgmt_account_id)
    config.account_ids = [log_account_id, int(workload_account_id)]

    account_ids = get_account_ids_in_scope()

    expected_accounts = [workload_account_id, log_account_id, mgmt_account_id]
    assert sorted(account_ids) == sorted(expected_accounts)
