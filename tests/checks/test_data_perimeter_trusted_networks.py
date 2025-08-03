import pytest

from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks.data_perimeter_trusted_networks import (
    DataPerimeterTrustedNetworksCheck,
)
from tests.factories import build_ou
from tests.factories import build_rcp
from tests.factories import build_scp
from tests.factories import create_config_for_org
from tests.factories import create_organization


def trusted_networks_rcp():
    return {
        "Statement": [
            dict(
                Effect="Deny",
                Action=[
                    "s3:*",
                    "sqs:*",
                    "kms:*",
                    "secretsmanager:*",
                    "sts:AssumeRole",
                    "sts:DecodeAuthorizationMessage",
                    "sts:GetAccessKeyInfo",
                    "sts:GetFederationToken",
                    "sts:GetServiceBearerToken",
                    "sts:GetSessionToken",
                    "sts:SetContext",
                ],
                Resource="*",
                Principal="*",
                Condition={
                    "NotIpAddressIfExists": {"aws:SourceIp": ["66.0.0.0/8"]},
                    "StringNotEqualsIfExists": {
                        "aws:SourceVpc": ["vpc-12345678"],
                        "aws:PrincipalTag/dp:exclude:network": "true",
                        "aws:PrincipalAccount": [
                            "1234567890",
                            "1234567891",
                            "1234567892",
                            "1234567893",
                        ],
                        "aws:ResourceTag/dp:exclude:network": "true",
                    },
                    "BoolIfExists": {
                        "aws:PrincipalIsAWSService": "false",
                        "aws:ViaAWSService": "false",
                    },
                    "ArnNotLikeIfExists": {
                        "aws:PrincipalArn": [
                            "arn:aws:iam::*:role/aws:ec2-infrastructure"
                        ]
                    },
                    "StringEquals": {"aws:PrincipalTag/dp:include:network": "true"},
                },
            )
        ]
    }


def trusted_networks_scp():
    return {
        "Statement": [
            dict(
                Effect="Deny",
                NotAction=[
                    "es:ES*",
                    "dax:GetItem",
                    "dax:BatchGetItem",
                    "dax:Query",
                    "dax:Scan",
                    "dax:PutItem",
                    "dax:UpdateItem",
                    "dax:DeleteItem",
                    "dax:BatchWriteItem",
                    "dax:ConditionCheckItem",
                    "neptune-db:*",
                    "kafka-cluster:*",
                    "elasticfilesystem:client*",
                    "rds-db:connect",
                ],
                Resource="*",
                Principal="*",
                Condition={
                    "BoolIfExists": {"aws:ViaAWSService": "false"},
                    "NotIpAddressIfExists": {"aws:SourceIp": ["66.0.0.0/8"]},
                    "StringNotEqualsIfExists": {"aws:SourceVpc": ["vpc-12345678"]},
                    "ArnNotLikeIfExists": {
                        "aws:PrincipalArn": [
                            "arn:aws:iam::12345676887:role/trusted-role"
                        ]
                    },
                },
            )
        ]
    }


@pytest.fixture
def check():
    return DataPerimeterTrustedNetworksCheck()


def test_no_policies(check):
    create_config_for_org()
    create_organization()
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "not enforced by both SCPs and RCPs" in result.reason


def test_scp_attached_to_root_ou(check):
    create_config_for_org()
    create_organization(
        root_ou=build_ou(scps=[build_scp(content=trusted_networks_scp())]),
    )
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "not enforced by both SCPs and RCPs" in result.reason


def test_scp_attached_to_all_top_level_ous(check):
    create_config_for_org()
    create_organization(
        root_ou=build_ou(
            child_ous=[
                build_ou(scps=[build_scp(content=trusted_networks_scp())]),
                build_ou(scps=[build_scp(content=trusted_networks_scp())]),
            ]
        )
    )
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "not enforced by both SCPs and RCPs" in result.reason


def test_rcp_attached_to_root_ou(check):
    create_config_for_org()
    create_organization(
        root_ou=build_ou(rcps=[build_rcp(content=trusted_networks_rcp())]),
    )
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "not enforced by both SCPs and RCPs" in result.reason


def test_rcp_attached_to_all_top_level_ous(check):
    create_config_for_org()
    create_organization(
        root_ou=build_ou(
            child_ous=[
                build_ou(rcps=[build_rcp(content=trusted_networks_rcp())]),
                build_ou(rcps=[build_rcp(content=trusted_networks_rcp())]),
            ]
        )
    )
    result = check.run()
    assert result.status == CheckStatus.FAIL
    assert "not enforced by both SCPs and RCPs" in result.reason


def test_both_scp_and_rcp_attached_to_root_ou(check):
    create_config_for_org()
    create_organization(
        root_ou=build_ou(
            scps=[build_scp(content=trusted_networks_scp())],
            rcps=[build_rcp(content=trusted_networks_rcp())],
        ),
    )
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert "enforced by both SCPs and RCPs" in result.reason


def test_both_scp_and_rcp_attached_to_top_level_ous(check):
    create_organization(
        root_ou=build_ou(
            child_ous=[
                build_ou(
                    scps=[build_scp(content=trusted_networks_scp())],
                    rcps=[build_rcp(content=trusted_networks_rcp())],
                ),
                build_ou(
                    scps=[build_scp(content=trusted_networks_scp())],
                    rcps=[build_rcp(content=trusted_networks_rcp())],
                ),
            ]
        )
    )
    result = check.run()
    assert result.status == CheckStatus.PASS
    assert "enforced by both SCPs and RCPs" in result.reason
