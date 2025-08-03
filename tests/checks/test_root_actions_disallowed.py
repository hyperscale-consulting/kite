import pytest

from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks import RootActionsDisallowedCheck
from tests.factories import build_ou
from tests.factories import build_scp
from tests.factories import create_config_for_org
from tests.factories import create_config_for_standalone_account
from tests.factories import create_organization

mgmt_account_id = "123456789012"


def scp_with_deny_star_arnlike_root():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"ArnLike": {"aws:principalarn": "arn:*:iam::*:root"}},
            }
        ],
    }


def scp_with_deny_star_stringlike_root():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"StringLike": {"aws:PrincipalArn": "arn:*:iam::*:root"}},
            }
        ],
    }


def scp_with_deny_star_arnlike_non_root():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "ArnLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:user/*"}
                },
            }
        ],
    }


def scp_with_deny_star_arnlike_root_and_multiple_actions():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": [
                    "*",
                    "s3:GetObject",
                ],
                "Resource": "*",
                "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:*:iam::*:root"}},
            }
        ],
    }


def scp_with_deny_star_arnlike_root_and_multiple_statements():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:*:iam::*:root"}},
            },
        ],
    }


def scp_with_deny_star_without_condition():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }


def invalid_scp():
    return {"invalid": "json"}


def test_check_no_org():
    create_config_for_standalone_account()
    check = RootActionsDisallowedCheck()
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert result.reason is not None
    assert "AWS Organizations is not being used" in result.reason


@pytest.mark.parametrize(
    "scp_content",
    [
        scp_with_deny_star_arnlike_root(),
        scp_with_deny_star_stringlike_root(),
        scp_with_deny_star_arnlike_root_and_multiple_actions(),
        scp_with_deny_star_arnlike_root_and_multiple_statements(),
    ],
)
def test_check_root_has_scp(scp_content):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(scps=[build_scp(content=scp_content)]),
    )

    check = RootActionsDisallowedCheck()
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert result.reason == "Disallow root actions SCP is attached to the root OU."


def test_check_all_top_level_have_scp():
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(scps=[build_scp(content=scp_with_deny_star_arnlike_root())]),
                build_ou(scps=[build_scp(content=scp_with_deny_star_arnlike_root())]),
                build_ou(
                    scps=[
                        build_scp(
                            content=scp_with_deny_star_arnlike_root_and_multiple_statements()
                        )
                    ]
                ),
                build_ou(
                    scps=[
                        build_scp(
                            content=scp_with_deny_star_arnlike_root_and_multiple_actions()
                        )
                    ]
                ),
            ]
        ),
    )

    check = RootActionsDisallowedCheck()
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert (
        result.reason == "Disallow root actions SCP is attached to all top-level OUs."
    )


def test_check_some_top_level_have_scp():
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(scps=[build_scp(content=scp_with_deny_star_arnlike_root())]),
                build_ou(scps=[build_scp(content=scp_with_deny_star_arnlike_root())]),
                build_ou(
                    scps=[build_scp(content=scp_with_deny_star_arnlike_non_root())]
                ),
            ]
        ),
    )

    check = RootActionsDisallowedCheck()
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert result.reason == (
        "Disallow root actions SCP is not attached to the root OU or all top-level OUs."
    )


@pytest.mark.parametrize(
    "scp_content",
    [
        scp_with_deny_star_without_condition(),
        invalid_scp(),
        scp_with_deny_star_arnlike_non_root(),
    ],
)
def test_check_root_does_not_have_scp(scp_content):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization(
        mgmt_account_id=mgmt_account_id,
        root_ou=build_ou(scps=[build_scp(content=scp_content)]),
    )

    check = RootActionsDisallowedCheck()
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert result.reason == (
        "Disallow root actions SCP is not attached to the root OU or all top-level OUs."
    )
