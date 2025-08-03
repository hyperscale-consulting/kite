import pytest

from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks.account_separation import AccountSeparationCheck
from tests.factories import build_account
from tests.factories import build_ou
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization

mgmt_account_id = "123456789012"
workload1_account_id = "210987654321"
workload2_account_id = "321098765432"


@pytest.fixture
def check():
    return AccountSeparationCheck()


def test_account_separation_check_no_org(check):
    create_config_for_standalone_account()
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "AWS Organizations is not being used" in result.reason


def test_check_account_separation(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(
                    name="Workloads",
                    accounts=[
                        build_account(id=workload1_account_id, name="Test account 1"),
                        build_account(id=workload2_account_id, name="Test account 2"),
                    ],
                )
            ]
        ),
    )
    result = check.run()

    assert result.status == CheckStatus.MANUAL
    print(result.context)
    assert "└── OU: Workloads" in result.context
    assert f"    ├── Account: Test account 1 ({workload1_account_id})" in result.context
    assert f"    └── Account: Test account 2 ({workload2_account_id})" in result.context
