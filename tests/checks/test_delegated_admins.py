import pytest

from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks import DelegatedAdminForSecurityServices
from hyperscale.kite.data import save_delegated_admins
from hyperscale.kite.models import DelegatedAdmin
from tests.factories import build_account
from tests.factories import build_delegated_admin
from tests.factories import build_ou
from tests.factories import create_config
from tests.factories import create_organization

mgmt_account_id = "1111111111111"
audit_account_id = "333333333333"
audit_account_email = "audit@example.com"
audit_account_name = "Audit"


@pytest.fixture
def check():
    return DelegatedAdminForSecurityServices()


def test_organizations_not_used(check):
    result = check.run()
    assert result.status == CheckStatus.PASS


def test_no_delegated_admins(check):
    create_organization()
    result = check.run()
    assert result.status == CheckStatus.FAIL


def test_delegated_admins_for_all_services(check):
    create_config(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(accounts=[build_account()]),
            ]
        ),
    )
    save_delegated_admins(
        mgmt_account_id,
        [
            build_delegated_admin(
                account_id=audit_account_id,
                service_principal=service_principal,
                account_email=audit_account_email,
                account_name=audit_account_name,
            )
            for service_principal in [
                "securityhub.amazonaws.com",
                "inspector2.amazonaws.com",
                "macie.amazonaws.com",
                "detective.amazonaws.com",
                "guardduty.amazonaws.com",
            ]
        ],
    )
    result = check.run()
    assert result.status == CheckStatus.MANUAL
    assert result.context == (
        "Delegated Administrators for Security Services:"
        "\n\n"
        f"securityhub.amazonaws.com: {audit_account_name} ({audit_account_id}) - "
        f"{audit_account_email}"
        "\n\n"
        f"inspector2.amazonaws.com: {audit_account_name} ({audit_account_id}) - "
        "audit@example.com"
        "\n\n"
        f"macie.amazonaws.com: {audit_account_name} ({audit_account_id}) - "
        f"{audit_account_email}"
        "\n\n"
        f"detective.amazonaws.com: {audit_account_name} ({audit_account_id}) - "
        "audit@example.com"
        "\n\n"
        f"guardduty.amazonaws.com: {audit_account_name} ({audit_account_id}) - "
        f"{audit_account_email}"
        "\n"
    )


def test_delegated_admin_for_one_services(check):
    create_config(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(accounts=[build_account()]),
            ]
        ),
    )
    save_delegated_admins(
        mgmt_account_id,
        [
            delegated_admin(audit_account_id, "guardduty.amazonaws.com"),
        ],
    )
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
