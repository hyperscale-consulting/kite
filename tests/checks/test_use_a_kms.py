from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.use_a_kms import UseAKmsCheck
from hyperscale.kite.data import save_kms_keys
from tests.factories import create_config_for_standalone_account

account_id = "123456789012"
region = "eu-west-2"


def test_external_key():
    create_config_for_standalone_account(
        account_ids=[account_id], active_regions=[region]
    )

    kms_keys = [
        {
            "KeyId": "customer-external-key",
            "KeyManager": "CUSTOMER",
            "Origin": "EXTERNAL",
        },
    ]
    save_kms_keys(account_id, region, kms_keys)

    result = UseAKmsCheck().run()

    assert result.status == CheckStatus.MANUAL
    assert "Keys stored and generated in a HSM" not in result.context
    assert "Keys generated outside of a HSM" in result.context
    assert "customer-external-key" in result.context


def test_all_hsm_key():
    create_config_for_standalone_account(
        account_ids=[account_id], active_regions=[region]
    )

    kms_keys = [
        {
            "KeyId": "customer-cloudhsm-key",
            "KeyManager": "CUSTOMER",
            "Origin": "AWS_CLOUDHSM",
        },
        {
            "KeyId": "customer-external-key-store-key",
            "KeyManager": "CUSTOMER",
            "Origin": "EXTERNAL_KEY_STORE",
        },
        {
            "KeyId": "customer-aws-kms-key",
            "KeyManager": "CUSTOMER",
            "Origin": "AWS_KMS",
        },
    ]
    save_kms_keys(account_id, region, kms_keys)

    result = UseAKmsCheck().run()

    assert result.status == CheckStatus.MANUAL
    assert "Keys stored and generated in a HSM" in result.context
    assert "Keys generated outside of a HSM" not in result.context


def test_ignore_aws_managed_keys():
    create_config_for_standalone_account(
        account_ids=[account_id], active_regions=[region]
    )

    kms_keys = [
        {"KeyId": "aws-key", "KeyManager": "AWS"},
    ]
    save_kms_keys(account_id, region, kms_keys)

    result = UseAKmsCheck().run()

    assert result.status == CheckStatus.MANUAL
    assert "aws-key" not in result.context
    assert "No customer-managed AWS KMS keys could be found"


def test_no_keys():
    create_config_for_standalone_account(
        account_ids=[account_id], active_regions=[region]
    )

    result = UseAKmsCheck().run()

    assert result.status == CheckStatus.MANUAL
    assert "aws-key" not in result.context
    assert "No customer-managed AWS KMS keys could be found"
