import pytest

from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks import TrustedDelegatedAdminsCheck
from hyperscale.kite.data import save_delegated_admins
from tests.factories import build_account
from tests.factories import build_delegated_admin
from tests.factories import build_ou
from tests.factories import create_config
from tests.factories import create_organization

audit_account_id = "333333333333"
backup_account_id = "444444444444"
mgmt_account_id = "1111111111111"


@pytest.fixture
def check():
    return TrustedDelegatedAdminsCheck()


def test_organizations_not_used(check):
    create_config(mgmt_account_id=mgmt_account_id)
    result = check.run()
    assert result.status == CheckStatus.PASS


def test_no_delegated_admins(check):
    create_config(mgmt_account_id=mgmt_account_id)
    create_organization()
    result = check.run()
    assert result.status == CheckStatus.PASS


def test_lists_all_admins_for_manual_check(check):
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
        account_id=mgmt_account_id,
        admins=[
            build_delegated_admin(
                account_id=audit_account_id,
                service_principal="securityhub.amazonaws.com",
                account_email="audit@example.com",
                account_name="Audit Account",
            ),
            build_delegated_admin(
                account_id=backup_account_id,
                service_principal="backup.amazonaws.com",
                account_email="backup@example.com",
                account_name="Backup Account",
            ),
            build_delegated_admin(
                account_id=audit_account_id,
                service_principal="detective.amazonaws.com",
                account_email="audit@example.com",
                account_name="Audit Account",
            ),
            build_delegated_admin(
                account_id=audit_account_id,
                service_principal="guardduty.amazonaws.com",
                account_email="audit@example.com",
                account_name="Audit Account",
            ),
        ],
    )
    result = check.run()
    assert result.status == CheckStatus.MANUAL
    assert result.context == (
        "Delegated Administrators:\n\n"
        f"Account: Audit Account ({audit_account_id})"
        "\n"
        "Email: audit@example.com\n"
        "Services:\n"
        "  - securityhub.amazonaws.com\n"
        "  - detective.amazonaws.com\n"
        "  - guardduty.amazonaws.com\n"
        "\n"
        f"Account: Backup Account ({backup_account_id})"
        "\n"
        "Email: backup@example.com\n"
        "Services:\n"
        "  - backup.amazonaws.com\n\n"
    )
