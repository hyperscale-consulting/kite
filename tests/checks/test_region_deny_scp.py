import pytest

from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks.region_deny_scp import RegionDenyScpCheck
from tests.factories import build_ou
from tests.factories import build_scp
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization

mgmt_account_id = "123456789012"
allowed_regions = ["us-east-1", "us-west-2", "eu-west-2"]


@pytest.fixture
def check():
    return RegionDenyScpCheck()


def region_deny_scp(regions):
    return {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:RequestedRegion": regions}},
            }
        ]
    }


def deny_disallowed_regions_scp():
    return region_deny_scp(allowed_regions)


def test_check_no_org(check):
    create_config_for_standalone_account(active_regions=allowed_regions)
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert result.reason is not None
    assert "AWS Organizations is not being used" in result.reason


def test_check_root_has_scp(check):
    create_config_for_org(active_regions=allowed_regions)
    create_organization(
        root_ou=build_ou(scps=[build_scp(content=deny_disallowed_regions_scp())]),
    )

    result = check.run()
    assert result.status == CheckStatus.PASS
    assert "Region deny SCP is attached to the root OU" in result.reason


def test_check_all_top_level_have_scp(check):
    create_config_for_org(active_regions=allowed_regions)
    create_organization(
        root_ou=build_ou(
            child_ous=[
                build_ou(scps=[build_scp(content=deny_disallowed_regions_scp())]),
                build_ou(scps=[build_scp(content=deny_disallowed_regions_scp())]),
                build_ou(scps=[build_scp(content=deny_disallowed_regions_scp())]),
                build_ou(scps=[build_scp(content=deny_disallowed_regions_scp())]),
            ]
        ),
    )

    result = check.run()
    assert result.status == CheckStatus.PASS
    assert "Region deny SCP is attached to all top-level OUs" in result.reason


def test_no_scp(check):
    create_config_for_org(active_regions=allowed_regions)
    create_organization()
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "Region deny SCP is not attached to the root OU" in result.reason


def test_one_ou_with_missing_scp(check):
    create_config_for_org(active_regions=allowed_regions)
    create_organization(
        root_ou=build_ou(
            child_ous=[
                build_ou(scps=[build_scp(content=deny_disallowed_regions_scp())]),
                build_ou(scps=[]),
                build_ou(scps=[build_scp(content=deny_disallowed_regions_scp())]),
            ]
        ),
    )

    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "Region deny SCP is not attached" in result.reason


def test_no_regions_configured(check):
    create_config_for_org(active_regions=[])
    create_organization(
        root_ou=build_ou(scps=[build_scp(content=deny_disallowed_regions_scp())]),
    )
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "No active regions configured" in result.reason


def test_scp_does_not_deny_all_regions(check):
    create_config_for_org(active_regions=allowed_regions)
    create_organization(
        root_ou=build_ou(scps=[build_scp(content=region_deny_scp(["us-west-2"]))]),
    )
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "Region deny SCP is not attached" in result.reason
