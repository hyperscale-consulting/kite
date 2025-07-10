import pytest

from kite.checks.kms_confused_deputy_protection.check import (
    check_kms_confused_deputy_protection,
)
from kite.data import save_kms_keys


@pytest.fixture
def kms_key_with_protection(workload_account_id, organization):
    keys = [
        {
            "KeyId": "1234567890",
            "KeyArn": f"arn:aws:kms:us-east-1:{workload_account_id}:key/1234567890",
            "Policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "sns.amazonaws.com"
                        },
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                        "Condition": {
                            "StringEquals": {
                                "aws:SourceAccount": workload_account_id
                            }
                        }
                    }
                ]
            }
        }
    ]
    save_kms_keys(workload_account_id, "us-east-1", keys)
    return keys


@pytest.fixture
def kms_key_without_protection(workload_account_id, organization):
    keys = [
        {
            "KeyId": "1234567890",
            "KeyArn": f"arn:aws:kms:us-east-1:{workload_account_id}:key/1234567890",
            "Policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "sns.amazonaws.com"
                        },
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                    }
                ]
            }
        }
    ]
    save_kms_keys(workload_account_id, "us-east-1", keys)
    return keys


def test_kms_confused_deputy_protection(kms_key_with_protection):
    result = check_kms_confused_deputy_protection()
    assert result["details"]["vulnerable_keys"] == []
    assert result["status"] == "PASS"


def test_kms_confused_deputy_protection_with_vulnerable_key(kms_key_without_protection):
    result = check_kms_confused_deputy_protection()
    assert result["status"] == "FAIL"
