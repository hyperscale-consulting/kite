import pytest

from kite.checks import CheckStatus
from kite.checks import DelegatedAdminForSecurityServices
from kite.data import save_delegated_admins
from kite.models import DelegatedAdmin


@pytest.fixture
def check():
    return DelegatedAdminForSecurityServices()


def test_organizations_not_used(check):
    result = check.run()
    assert result.status == CheckStatus.PASS


def test_no_delegated_admins(check, organization_factory):
    organization_factory()
    result = check.run()
    assert result.status == CheckStatus.FAIL


def test_delegated_admins_for_all_services(
    check, organization_factory, ou_factory, account_factory, config
):
    audit_account_id = "333333333333"
    mgmt_account_id = "1111111111111"
    organization_factory(
        mgmt_account_id=mgmt_account_id,
        root_ou=ou_factory(
            child_ous=[
                ou_factory(accounts=[account_factory()]),
            ]
        ),
    )
    save_delegated_admins(
        mgmt_account_id,
        [
            delegated_admin(audit_account_id, "securityhub.amazonaws.com"),
            delegated_admin(audit_account_id, "inspector2.amazonaws.com"),
            delegated_admin(audit_account_id, "macie.amazonaws.com"),
            delegated_admin(audit_account_id, "detective.amazonaws.com"),
            delegated_admin(audit_account_id, "guardduty.amazonaws.com"),
        ],
    )
    config.management_account_id = mgmt_account_id
    result = check.run()
    assert result.status == CheckStatus.MANUAL
    assert result.context == (
        "Delegated Administrators for Security Services:"
        "\n\n"
        f"securityhub.amazonaws.com: Test Account ({333333333333}) - audit@example.com"
        "\n\n"
        f"inspector2.amazonaws.com: Test Account ({333333333333}) - audit@example.com"
        "\n\n"
        f"macie.amazonaws.com: Test Account ({333333333333}) - audit@example.com"
        "\n\n"
        f"detective.amazonaws.com: Test Account ({333333333333}) - audit@example.com"
        "\n\n"
        f"guardduty.amazonaws.com: Test Account ({333333333333}) - audit@example.com"
        "\n"
    )


def test_delegated_admin_for_one_services(
    check, organization_factory, ou_factory, account_factory, config
):
    audit_account_id = "333333333333"
    mgmt_account_id = "1111111111111"
    organization_factory(
        mgmt_account_id=mgmt_account_id,
        root_ou=ou_factory(
            child_ous=[
                ou_factory(accounts=[account_factory()]),
            ]
        ),
    )
    save_delegated_admins(
        mgmt_account_id,
        [
            delegated_admin(audit_account_id, "guardduty.amazonaws.com"),
        ],
    )
    config.management_account_id = mgmt_account_id
    result = check.run()
    assert result.status == CheckStatus.FAIL


def delegated_admin(account_id, service_principal):
    return DelegatedAdmin(
        id=account_id,
        arn=f"arn:aws:organizations:::111111111111:account/{account_id}",
        name="Test Account",
        email="audit@example.com",
        status="Active",
        joined_method="CREATED",
        joined_timestamp="2021-01-01T00:00:00Z",
        delegation_enabled_date="2021-01-01T00:00:00Z",
        service_principal=service_principal,
    )
