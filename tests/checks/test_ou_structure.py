from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks.ou_structure import OuStructureCheck
from tests.factories import build_account
from tests.factories import build_ou
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization

mgmt_account_id = "123456789012"
workload_account_id = "666666666666"


def test_no_org():
    create_config_for_standalone_account()
    result = OuStructureCheck().run()
    assert result.status == CheckStatus.FAIL
    assert result.reason is not None
    assert (
        result.reason
        == "AWS Organizations is not being used, so OU structure cannot be assessed."
    )


def test_org():
    create_config_for_org(mgmt_account_id)
    create_organization(
        mgmt_account_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(
                    name="Workloads",
                    accounts=[
                        build_account(id=workload_account_id, name="Test account")
                    ],
                )
            ],
        ),
    )
    result = OuStructureCheck().run()
    assert result.status == CheckStatus.MANUAL
    assert result.context is not None
    assert "└── OU: Workloads" in result.context
    assert "    └── Account: Test account (666666666666)" in result.context
