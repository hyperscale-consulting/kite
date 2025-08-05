import json

import pytest
from botocore.exceptions import ClientError

from hyperscale.kite.organizations import fetch_delegated_admins
from hyperscale.kite.organizations import fetch_organization
from tests.clients import OrganizationsClient


def test_no_org(stub_aws_session):
    client = OrganizationsClient(error_code="AWSOrganizationsNotInUseException")
    stub_aws_session.register_client(client, "organizations")
    with pytest.raises(ClientError) as excinfo:
        fetch_organization(stub_aws_session)
    assert (
        excinfo.value.response["Error"]["Code"] == "AWSOrganizationsNotInUseException"
    )


def test_raises_access_denied(stub_aws_session):
    client = OrganizationsClient(error_code="AccessDeniedException")
    stub_aws_session.register_client(client, "organizations")
    with pytest.raises(ClientError) as excinfo:
        fetch_organization(stub_aws_session)
    assert excinfo.value.response["Error"]["Code"] == "AccessDeniedException"


def test_fetch_org(stub_aws_session):
    org_client = OrganizationsClient()
    stub_aws_session.register_client(org_client, "organizations")

    id = "o-exampleorgid"
    master_account_id = "123456789012"
    feature_set = "ALL"

    org_client.set_organization(
        id=id,
        master_account_id=master_account_id,
        feature_set=feature_set,
    )

    root_id = "r-examplerootid"
    org_client.set_root(
        root_id=root_id,
    )

    policy_id = "p-rootscp"
    policy_name = "RootSCP"
    policy_content = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }
    workload_ou_id = "workload-ou-id"

    org_client.add_policy(
        policy_id=policy_id,
        policy_type="SERVICE_CONTROL_POLICY",
        name=policy_name,
        content=policy_content,
    )
    org_client.add_policy_for_target(
        target_id=root_id,
        policy_id=policy_id,
    )

    org_client.add_account(
        parent=root_id, account_id="1111111111111", name="Management Account"
    )

    org_client.add_child(
        parent_id=root_id, child_id=workload_ou_id, child_type="ORGANIZATIONAL_UNIT"
    )
    workload_ou_name = "Workload OU"
    org_client.add_ou(workload_ou_id, name=workload_ou_name)

    prod_ou_id = "prod-ou-id"
    org_client.add_child(
        parent_id=workload_ou_id, child_id=prod_ou_id, child_type="ORGANIZATIONAL_UNIT"
    )
    prod_ou_name = "Prod OU"
    org_client.add_ou(prod_ou_id, name=prod_ou_name)

    prod_scp_id = "prod_scp"
    org_client.add_policy_for_target(prod_ou_id, policy_id=prod_scp_id)
    org_client.add_policy(prod_scp_id, policy_type="SERVICE_CONTROL_POLICY")

    prod_rcp_id = "prod_rcp"
    org_client.add_policy_for_target(prod_ou_id, policy_id=prod_rcp_id)
    org_client.add_policy(prod_rcp_id, policy_type="RESOURCE_CONTROL_POLICY")

    prod_tp_id = "prod_tp"
    org_client.add_policy_for_target(prod_ou_id, policy_id=prod_tp_id)
    org_client.add_policy(prod_tp_id, policy_type="TAG_POLICY")

    prod_account_id = "2222222222222"
    prod_account_name = "Prod Account"
    org_client.add_account(prod_ou_id, prod_account_id, name=prod_account_name)

    org = fetch_organization(stub_aws_session)
    assert org is not None
    assert org.id == id
    assert org.master_account_id == master_account_id
    assert org.feature_set == "ALL"
    assert org.root.id == root_id
    assert len(org.root.scps) == 1

    root_scp = org.root.scps[0]
    assert root_scp.id == policy_id
    assert root_scp.name == policy_name
    assert root_scp.content == json.dumps(policy_content)

    root_accounts = org.root.accounts
    assert len(root_accounts) == 1
    mgmt_account = root_accounts[0]
    mgmt_account.id = master_account_id

    child_ous = org.root.child_ous
    assert len(child_ous) == 1

    workload_ou = child_ous[0]
    assert workload_ou.id == workload_ou_id
    assert workload_ou.name == "Workload OU"
    assert workload_ou.accounts == []
    assert workload_ou.scps == []
    assert len(workload_ou.child_ous) == 1

    prod_ou = workload_ou.child_ous[0]
    assert prod_ou.id == prod_ou_id
    assert prod_ou.name == prod_ou_name
    assert len(prod_ou.scps) == 1
    assert len(prod_ou.rcps) == 1
    assert len(prod_ou.tag_policies) == 1
    assert len(prod_ou.accounts) == 1

    workload_account = prod_ou.accounts[0]
    assert workload_account.name == prod_account_name
    assert workload_account.id == prod_account_id


def test_fetch_deletgated_admins_no_org(stub_aws_session):
    client = OrganizationsClient(error_code="AWSOrganizationsNotInUseException")
    stub_aws_session.register_client(client, "organizations")
    delegated_admins = fetch_delegated_admins(stub_aws_session)
    assert delegated_admins == []


def test_fetch_delegated_admins_access_denied(stub_aws_session):
    client = OrganizationsClient(error_code="AccessDeniedException")
    stub_aws_session.register_client(client, "organizations")
    with pytest.raises(ClientError) as excinfo:
        fetch_delegated_admins(stub_aws_session)
    assert excinfo.value.response["Error"]["Code"] == "AccessDeniedException"


def test_fetch_delegated_admins(stub_aws_session):
    client = OrganizationsClient()
    stub_aws_session.register_client(client, "organizations")

    id = "o-exampleorgid"
    master_account_id = "123456789012"
    feature_set = "ALL"

    client.set_organization(
        id=id,
        master_account_id=master_account_id,
        feature_set=feature_set,
    )

    root_id = "root_id"
    client.set_root(root_id=root_id)

    security_ou_id = "sec-ou"
    client.add_child(
        parent_id=root_id, child_id=security_ou_id, child_type="ORGANIZATIONAL_UNIT"
    )
    client.add_ou(security_ou_id, name="Security")

    audit_account_id = "2222222222222"
    client.add_account(security_ou_id, audit_account_id, name="Audit")
    client.add_delegated_admin(
        audit_account_id,
        service_principal="securityhub.amazonaws.com",
    )
    client.add_delegated_admin(
        audit_account_id,
        service_principal="guardduty.amazonaws.com",
    )

    admins = fetch_delegated_admins(stub_aws_session)
    assert len(admins) == 2

    assert admins[0].id == audit_account_id
    assert admins[0].service_principal == "securityhub.amazonaws.com"

    assert admins[1].id == audit_account_id
    assert admins[1].service_principal == "guardduty.amazonaws.com"
