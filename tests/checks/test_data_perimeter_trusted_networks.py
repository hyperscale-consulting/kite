import json

import pytest

from kite.checks.data_perimeter_trusted_networks import (
    check_data_perimeter_trusted_networks,
)
from kite.data import save_organization
from kite.models import ControlPolicy


@pytest.fixture
def trusted_networks_rcp():
    return ControlPolicy(
        id="666",
        name="Trusted Networks RCP",
        description="Trusted Networks RCP",
        arn="arn:aws:iam::1234567890:policy/TrustedNetworksRCP",
        type="RESOURCE_CONTROL_POLICY",
        content=json.dumps(
            {
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
                            "StringEquals": {
                                "aws:PrincipalTag/dp:include:network": "true"
                            },
                        },
                    )
                ]
            }
        ),
    )


@pytest.fixture
def trusted_networks_scp():
    return ControlPolicy(
        id="123",
        name="Trusted Networks",
        description="Trusted Networks",
        arn="arn:aws:iam::1234567890:policy/TrustedNetworks",
        type="SERVICE_CONTROL_POLICY",
        content=json.dumps(
            {
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
                            "StringNotEqualsIfExists": {
                                "aws:SourceVpc": ["vpc-12345678"]
                            },
                            "ArnNotLikeIfExists": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::12345676887:role/trusted-role"
                                ]
                            },
                        },
                    )
                ]
            }
        ),
    )


@pytest.fixture
def scp_attached_to_root_ou(organization, trusted_networks_scp, mgmt_account_id):
    organization.root.scps.append(trusted_networks_scp)
    save_organization(mgmt_account_id, organization)
    yield organization


@pytest.fixture
def scp_attached_to_all_top_level_ous(
    organization, trusted_networks_scp, mgmt_account_id
):
    for ou in organization.root.child_ous:
        ou.scps.append(trusted_networks_scp)
    save_organization(mgmt_account_id, organization)
    yield organization


@pytest.fixture
def rcp_attached_to_root_ou(organization, trusted_networks_rcp, mgmt_account_id):
    organization.root.rcps.append(trusted_networks_rcp)
    save_organization(mgmt_account_id, organization)
    yield organization


@pytest.fixture
def rcp_attached_to_all_top_level_ous(
    organization, trusted_networks_rcp, mgmt_account_id
):
    for ou in organization.root.child_ous:
        ou.rcps.append(trusted_networks_rcp)
    save_organization(mgmt_account_id, organization)
    yield organization


def test_no_policies(organization):
    result = check_data_perimeter_trusted_networks()
    assert result["status"] == "FAIL"
    assert "not enforced by both SCPs and RCPs" in result["details"]["message"]


def test_scp_attached_to_root_ou(scp_attached_to_root_ou):
    result = check_data_perimeter_trusted_networks()
    assert result["status"] == "FAIL"
    assert "not enforced by both SCPs and RCPs" in result["details"]["message"]


def test_scp_attached_to_all_top_level_ous(scp_attached_to_all_top_level_ous):
    result = check_data_perimeter_trusted_networks()
    assert result["status"] == "FAIL"
    assert "not enforced by both SCPs and RCPs" in result["details"]["message"]


def test_rcp_attached_to_root_ou(rcp_attached_to_root_ou):
    result = check_data_perimeter_trusted_networks()
    assert result["status"] == "FAIL"
    assert "not enforced by both SCPs and RCPs" in result["details"]["message"]


def test_rcp_attached_to_all_top_level_ous(rcp_attached_to_all_top_level_ous):
    result = check_data_perimeter_trusted_networks()
    assert result["status"] == "FAIL"
    assert "not enforced by both SCPs and RCPs" in result["details"]["message"]


def test_both_scp_and_rcp_attached_to_root_ou(
    organization, trusted_networks_scp, trusted_networks_rcp, mgmt_account_id
):
    # Add SCP to root OU
    organization.root.scps.append(trusted_networks_scp)
    organization.root.rcps.append(trusted_networks_rcp)

    save_organization(mgmt_account_id, organization)

    result = check_data_perimeter_trusted_networks()
    assert result["status"] == "PASS"
    assert "enforced by both SCPs and RCPs" in result["details"]["message"]


def test_both_scp_and_rcp_attached_to_top_level_ous(
    organization, trusted_networks_scp, trusted_networks_rcp, mgmt_account_id
):
    # Add SCP to all top-level OUs
    for ou in organization.root.child_ous:
        ou.scps.append(trusted_networks_scp)

    # Add RCP to all top-level OUs
    for ou in organization.root.child_ous:
        ou.rcps.append(trusted_networks_rcp)

    save_organization(mgmt_account_id, organization)

    result = check_data_perimeter_trusted_networks()
    assert result["status"] == "PASS"
    assert "enforced by both SCPs and RCPs" in result["details"]["message"]
