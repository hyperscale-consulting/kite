from hyperscale.kite.checks import UseLogsForAlertingCheck
from hyperscale.kite.checks.core import CheckStatus
from tests.factories import build_prowler_check_result
from tests.factories import create_config_for_standalone_account
from tests.factories import create_prowler_output_file

account1_id = "123456789012"
account2_id = "999999999999"
region1 = "us-east-1"
region2 = "eu-west-2"


def test_prowler_checks_pass_across_all_regions_and_accounts():
    create_config_for_standalone_account(
        account_ids=[account1_id, account2_id], active_regions=[region1, region2]
    )
    create_prowler_output_file(
        account1_id,
        [
            build_prowler_check_result(
                "guardduty_is_enabled", account1_id, region1, "PASS"
            ),
            build_prowler_check_result(
                "guardduty_is_enabled", account1_id, region2, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account1_id, region1, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account1_id, region2, "PASS"
            ),
            build_prowler_check_result(
                "guardduty_is_enabled", account2_id, region1, "PASS"
            ),
            build_prowler_check_result(
                "guardduty_is_enabled", account2_id, region2, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account2_id, region1, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account2_id, region2, "PASS"
            ),
        ],
    )

    result = UseLogsForAlertingCheck().run()
    print(result.context)
    assert result.status == CheckStatus.MANUAL
    assert (
        "SecurityHub Status: enabled across all accounts and regions" in result.context
    )
    assert "GuardDuty Status: enabled across all accounts and regions" in result.context


def test_prowler_checks_fail_in_one_account_and_region():
    create_config_for_standalone_account(
        account_ids=[account1_id, account2_id], active_regions=[region1, region2]
    )
    create_prowler_output_file(
        account1_id,
        [
            build_prowler_check_result(
                "guardduty_is_enabled", account1_id, region1, "FAIL"
            ),
            build_prowler_check_result(
                "guardduty_is_enabled", account1_id, region2, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account1_id, region1, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account1_id, region2, "PASS"
            ),
            build_prowler_check_result(
                "guardduty_is_enabled", account2_id, region1, "PASS"
            ),
            build_prowler_check_result(
                "guardduty_is_enabled", account2_id, region2, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account2_id, region1, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account2_id, region2, "PASS"
            ),
        ],
    )

    result = UseLogsForAlertingCheck().run()
    print(result.context)
    assert result.status == CheckStatus.MANUAL
    assert (
        "SecurityHub Status: enabled across all accounts and regions" in result.context
    )
    assert (
        "GuardDuty Status: *NOT* enabled across all accounts and regions"
        in result.context
    )


def test_prowler_checks_missing_in_one_account_and_region():
    create_config_for_standalone_account(
        account_ids=[account1_id, account2_id], active_regions=[region1, region2]
    )
    create_prowler_output_file(
        account1_id,
        [
            build_prowler_check_result(
                "guardduty_is_enabled", account1_id, region2, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account1_id, region1, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account1_id, region2, "PASS"
            ),
            build_prowler_check_result(
                "guardduty_is_enabled", account2_id, region1, "PASS"
            ),
            build_prowler_check_result(
                "guardduty_is_enabled", account2_id, region2, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account2_id, region1, "PASS"
            ),
            build_prowler_check_result(
                "securityhub_enabled", account2_id, region2, "PASS"
            ),
        ],
    )

    result = UseLogsForAlertingCheck().run()
    print(result.context)
    assert result.status == CheckStatus.MANUAL
    assert (
        "SecurityHub Status: enabled across all accounts and regions" in result.context
    )
    assert (
        "GuardDuty Status: *NOT* enabled across all accounts and regions"
        in result.context
    )
