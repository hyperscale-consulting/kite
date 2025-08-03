from hyperscale.kite.prowler import did_check_pass
from tests.factories import build_prowler_check_result
from tests.factories import create_config_for_standalone_account
from tests.factories import create_prowler_output_file

account_id = "123456789012"
different_account = "234567890123"
region = "us-east-1"
different_region = "eu-west-2"


def create_prowler_output():
    create_prowler_output_file(
        account_id,
        [
            build_prowler_check_result("passing_check", account_id, region, "PASS"),
            build_prowler_check_result("failing_check", account_id, region, "FAIL"),
        ],
    )


def test_did_check_pass():
    create_config_for_standalone_account()
    create_prowler_output()
    assert did_check_pass("passing_check", account_id, region)
    assert not did_check_pass("failing_check", account_id, region)
    assert not did_check_pass("not_found_check", account_id, region)
    assert not did_check_pass("passing_check", different_account, region)
    assert not did_check_pass("passing_check", account_id, different_region)
