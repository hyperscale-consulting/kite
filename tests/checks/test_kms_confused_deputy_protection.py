import pytest

from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks.kms_confused_deputy_protection import (
    KmsConfusedDeputyProtectionCheck,
)
from hyperscale.kite.data import save_kms_keys
from tests.factories import create_config_for_org
from tests.factories import create_organization_with_workload_account

workload_account_id = "123456789012"
mgmt_account_id = "111111111111"


@pytest.fixture
def check():
    return KmsConfusedDeputyProtectionCheck()


def kms_key_with_protection():
    keys = [
        {
            "KeyId": "1234567890",
            "Arn": f"arn:aws:kms:us-east-1:{workload_account_id}:key/1234567890",
            "Policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "sns.amazonaws.com"},
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": workload_account_id}
                        },
                    }
                ]
            },
        }
    ]
    save_kms_keys(workload_account_id, "us-east-1", keys)
    return keys


def kms_key_without_protection():
    keys = [
        {
            "KeyId": "1234567890",
            "Arn": f"arn:aws:kms:us-east-1:{workload_account_id}:key/1234567890",
            "Policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "sns.amazonaws.com"},
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                    }
                ]
            },
        }
    ]
    save_kms_keys(workload_account_id, "us-east-1", keys)
    return keys


def test_kms_confused_deputy_protection(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization_with_workload_account(
        workload_account_id=workload_account_id,
        mgmt_account_id=mgmt_account_id,
    )
    kms_key_with_protection()
    result = check.run()
    assert result.status == CheckStatus.PASS


def test_kms_confused_deputy_protection_with_vulnerable_key(check):
    create_config_for_org(mgmt_account_id=mgmt_account_id)
    create_organization_with_workload_account(
        workload_account_id=workload_account_id,
        mgmt_account_id=mgmt_account_id,
    )
    kms_key_without_protection()
    result = check.run()
    assert result.status == CheckStatus.FAIL
