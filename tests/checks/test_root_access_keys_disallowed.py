import pytest

from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.root_access_keys_disallowed import (
    RootAccessKeysDisallowedCheck,
)
from tests.factories import build_ou
from tests.factories import build_scp
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization

mgmt_account_id = "123456789012"


def scp_with_deny_create_access_key_arnlike_root():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "iam:CreateAccessKey",
                "Resource": "*",
                "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:*:iam::*:root"}},
            }
        ],
    }


def scp_with_deny_star_arnlike_root():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:*:iam::*:root"}},
            }
        ],
    }


def scp_with_deny_multi_action_arnlike_root():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["iam:CreateAccessKey", "iam:CreateRole"],
                "Resource": "*",
                "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:*:iam::*:root"}},
            }
        ],
    }


def scp_with_deny_create_access_key_stringlike_root():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "iam:CreateAccessKey",
                "Resource": "*",
                "Condition": {"StringLike": {"aws:PrincipalArn": "arn:*:iam::*:root"}},
            }
        ],
    }


@pytest.fixture
def check() -> RootAccessKeysDisallowedCheck:
    return RootAccessKeysDisallowedCheck()


def test_check_no_org(check):
    create_config_for_standalone_account()
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert result.reason is not None
    assert "AWS Organizations is not being used" in result.reason


@pytest.mark.parametrize(
    "scp_content",
    [
        scp_with_deny_star_arnlike_root(),
        scp_with_deny_create_access_key_arnlike_root(),
        scp_with_deny_multi_action_arnlike_root(),
        scp_with_deny_create_access_key_stringlike_root(),
    ],
)
def test_root_has_scp(check, scp_content):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(scps=[build_scp(content=scp_content)]),
    )
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert (
        result.reason
        == "Disallow root access keys creation SCP is attached to the root OU."
    )


def test_all_top_level_ous_have_scp(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(scps=[build_scp(content=scp_with_deny_star_arnlike_root())]),
                build_ou(scps=[build_scp(content=scp_with_deny_star_arnlike_root())]),
            ]
        ),
    )
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert (
        result.reason
        == "Disallow root access keys creation SCP is attached to all top-level OUs."
    )


def test_some_top_level_ous_have_scp(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(scps=[build_scp(content=scp_with_deny_star_arnlike_root())]),
                build_ou(scps=[]),
            ]
        ),
    )
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert (
        result.reason
        == "Disallow root access keys creation SCP is not attached to the root OU "
        "or all top-level OUs."
    )


def test_root_does_not_have_scp(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id, root_ou=build_ou(scps=[build_scp(content={})])
    )
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert (
        result.reason
        == "Disallow root access keys creation SCP is not attached to the root OU "
        "or all top-level OUs."
    )
