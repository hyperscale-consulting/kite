import json

import pytest

from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.s3_confused_deputy_protection import (
    S3ConfusedDeputyProtectionCheck,
)
from hyperscale.kite.data import save_bucket_metadata


@pytest.fixture
def check():
    return S3ConfusedDeputyProtectionCheck()


@pytest.fixture
def bucket_with_confused_deputy_protection(workload_account_id, organization):
    bucket = {
        "Name": "test-bucket",
        "Policy": json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "delivery.logs.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::test-bucket/*",
                        "Condition": {
                            "StringEquals": {"aws:SourceOrgID": organization.id}
                        },
                    }
                ]
            }
        ),
    }
    save_bucket_metadata(workload_account_id, [bucket])
    return bucket


@pytest.fixture
def bucket_with_confused_deputy_protection_upper_case(
    workload_account_id, organization
):
    bucket = {
        "Name": "test-bucket",
        "Policy": json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "delivery.logs.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::test-bucket/*",
                        "Condition": {
                            "StringEquals": {"AWS:SourceOrgID": organization.id}
                        },
                    }
                ]
            }
        ),
    }
    save_bucket_metadata(workload_account_id, [bucket])
    return bucket


@pytest.fixture
def bucket_with_confused_deputy_protection_upper_case_arn_like(workload_account_id):
    bucket = {
        "Name": "test-bucket",
        "Policy": json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "delivery.logs.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::test-bucket/*",
                        "Condition": {
                            "ArnLike": {
                                "AWS:SourceArn": ["arn:aws:iam::123456789012:user/*"]
                            }
                        },
                    }
                ]
            }
        ),
    }
    save_bucket_metadata(workload_account_id, [bucket])
    return bucket


@pytest.fixture
def bucket_with_no_confused_deputy_protection(workload_account_id):
    bucket = {
        "Name": "test-bucket",
        "Policy": json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "delivery.logs.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::test-bucket/*",
                    }
                ]
            }
        ),
    }
    save_bucket_metadata(workload_account_id, [bucket])
    return bucket


@pytest.fixture
def bucket_with_user_principal(workload_account_id):
    bucket = {
        "Name": "test-bucket",
        "Policy": json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::123456789012:user/test-user"
                        },
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::test-bucket/*",
                    }
                ]
            }
        ),
    }
    save_bucket_metadata(workload_account_id, [bucket])
    return bucket


@pytest.fixture
def no_org_config(workload_account_id, config):
    config.management_account_id = None
    config.account_ids = [workload_account_id]
    return config


def test_is_service_principal(check):
    """Test the _is_service_principal method."""
    assert check._is_service_principal("lambda.amazonaws.com") is True
    assert check._is_service_principal("s3.amazonaws.com") is True
    assert check._is_service_principal("arn:aws:iam::123456789012:user/test") is False
    assert check._is_service_principal("*") is False
    assert (
        check._is_service_principal(["lambda.amazonaws.com", "s3.amazonaws.com"])
        is True
    )
    assert (
        check._is_service_principal(
            ["lambda.amazonaws.com", "arn:aws:iam::123456789012:user/test"]
        )
        is True
    )
    assert (
        check._is_service_principal(["arn:aws:iam::123456789012:user/test", "*"])
        is False
    )


def test_s3_confused_deputy_protection(check, bucket_with_confused_deputy_protection):
    result = check.run()
    assert result.status == CheckStatus.PASS


def test_s3_no_confused_deputy_protection(
    check, bucket_with_no_confused_deputy_protection, no_org_config
):
    result = check.run()
    assert result.status == CheckStatus.FAIL


def test_s3_user_principal(check, bucket_with_user_principal, no_org_config):
    result = check.run()
    assert result.status == CheckStatus.PASS


def test_s3_confused_deputy_protection_upper_case(
    check, bucket_with_confused_deputy_protection_upper_case, no_org_config
):
    result = check.run()
    assert result.status == CheckStatus.PASS


def test_s3_confused_deputy_protection_upper_case_arn_like(
    check, bucket_with_confused_deputy_protection_upper_case_arn_like, no_org_config
):
    result = check.run()
    assert result.status == CheckStatus.PASS
