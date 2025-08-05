import json
from collections import defaultdict
from datetime import datetime
from datetime import time

from botocore.exceptions import ClientError


class ListPoliciesForTargetPaginator:
    def __init__(self, policies_for_target):
        self.policies_for_target = policies_for_target

    def paginate(self, TargetId, Filter):
        policies = self.policies_for_target.get(f"{TargetId}#{Filter}", [])
        return [{"Policies": policies}]


class ListAccountsForParentPaginator:
    def __init__(self, accounts_for_parent):
        self.accounts_for_parent = accounts_for_parent

    def paginate(self, ParentId):
        accounts = self.accounts_for_parent.get(ParentId, [])
        return [{"Accounts": accounts}]


class ListChildrenPaginator:
    def __init__(self, children):
        self.children = children

    def paginate(self, ParentId, ChildType):
        children = self.children.get(f"{ParentId}#{ChildType}", [])
        return [{"Children": children}]


class ListDelegatedAdministratorsPaginator:
    def __init__(self, delegated_admins, error_response=None):
        self.delegated_admins = delegated_admins
        self.error_response = error_response

    def paginate(self):
        if self.error_response:
            raise ClientError(self.error_response, "ListDelegatedAdministrators")
        delegated_admins = [
            {"Id": k, "Arn": v[0]["Arn"]} for k, v in self.delegated_admins.items()
        ]
        return [{"DelegatedAdministrators": delegated_admins}]


class ListDelegatedServicesForAccount:
    def __init__(self, delegated_admins):
        self.delegated_admins = delegated_admins

    def paginate(self, AccountId):
        services = [
            {
                "ServicePrincipal": e["ServicePrincipal"],
                "DelegationEnabledDate": e["DelegationEnabledDate"],
            }
            for e in self.delegated_admins[AccountId]
        ]
        return [{"DelegatedServices": services}]


class OrganizationsClient:
    def __init__(self, error_code=None):
        self.error_response = error_code and {"Error": {"Code": error_code}} or None
        self.error_code = error_code
        self.organization = None
        self.policies_for_target = defaultdict(list)
        self.policies = defaultdict(dict)
        self.accounts_for_parent = defaultdict(list)
        self.ous = defaultdict(dict)
        self.children = defaultdict(list)
        self.delegated_admins = defaultdict(list)
        self.paginators = {
            "list_policies_for_target": ListPoliciesForTargetPaginator(
                self.policies_for_target
            ),
            "list_accounts_for_parent": ListAccountsForParentPaginator(
                self.accounts_for_parent
            ),
            "list_children": ListChildrenPaginator(self.children),
            "list_delegated_administrators": ListDelegatedAdministratorsPaginator(
                self.delegated_admins, self.error_response
            ),
            "list_delegated_services_for_account": ListDelegatedServicesForAccount(
                self.delegated_admins
            ),
        }

    def get_paginator(self, operation_name):
        return self.paginators[operation_name]

    def describe_organization(self):
        if self.error_response:
            raise ClientError(self.error_response, "DescribeOrganization")
        return {"Organization": self.organization}

    def describe_policy(self, PolicyId):
        return {"Policy": self.policies[PolicyId]}

    def list_roots(self):
        return {"Roots": [self.root]}

    def describe_organizational_unit(self, OrganizationalUnitId):
        return {"OrganizationalUnit": self.ous[OrganizationalUnitId]}

    def describe_account(self, AccountId):
        account = self._get_account(AccountId)
        return {"Account": account}

    def _get_account(self, account_id):
        for a in self.accounts_for_parent.values():
            for account in a:
                if account["Id"] == account_id:
                    return account
        return None

    # methods to configure the test client
    def set_root(self, root_id="r-abc1"):
        if self.organization is None:
            raise ValueError("Organization must be set before setting roots.")
        self.root = {
            "Id": root_id,
            "Arn": (
                f"arn:aws:organizations::{self.master_account_id}:root/"
                f"{self.org_id}/{root_id}",
            ),
            "Name": "Root",
        }

    def add_policy(
        self,
        policy_id,
        name="TestPolicy",
        description="TestPolicy",
        content=None,
        policy_type="SERVICE_CONTROL_POLICY",
    ):
        content = content or {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        self.policies[policy_id] = {
            "PolicySummary": {
                "Id": policy_id,
                "Arn": (
                    f"arn:aws:organizations::{self.master_account_id}:policy/"
                    f"{self.org_id}/{policy_id}"
                ),
                "Name": name,
                "Type": policy_type,
                "Description": description,
            },
            "Content": json.dumps(content),
        }

    def add_policy_for_target(
        self,
        target_id,
        policy_id="p-examplepolicy",
        name="TestPolicy",
        policy_type="SERVICE_CONTROL_POLICY",
    ):
        self.policies_for_target[f"{target_id}#{policy_type}"].append(
            {
                "Id": policy_id,
                "Arn": (
                    f"arn:aws:organizations::{self.master_account_id}:policy/"
                    f"{self.org_id}/{policy_id}"
                ),
                "Name": name,
                "Type": policy_type,
            }
        )

    def set_organization(
        self,
        id="o-exampleorgid",
        master_account_id="123456789012",
        feature_set="ALL",
    ):
        self.org_id = id
        self.master_account_id = master_account_id
        self.organization = {
            "Id": id,
            "MasterAccountId": master_account_id,
            "Arn": f"arn:aws:organizations::{master_account_id}:organization/{id}",
            "FeatureSet": feature_set,
        }

    def add_account(
        self,
        parent: str,
        account_id: str,
        name: str = "Test Account",
        email: str = "test@exmaple.com",
        status: str = "ACTIVE",
        joined_method: str = "CREATED",
        joined_timestamp: time | None = None,
    ):
        self.accounts_for_parent[parent].append(
            {
                "Id": account_id,
                "Arn": (
                    f"arn:aws:organizations::{self.master_account_id}:account/"
                    f"{self.org_id}/{account_id}"
                ),
                "Name": name,
                "Email": email,
                "Status": status,
                "JoinedMethod": joined_method,
                "JoinedTimestamp": (
                    joined_timestamp and joined_timestamp or datetime.now()
                ),
            }
        )

    def add_child(self, parent_id, child_id, child_type="ORGANIZATIONAL_UNIT"):
        self.children[f"{parent_id}#{child_type}"].append({"Id": child_id})

    def add_ou(self, ou_id, name="TestOU"):
        self.ous[ou_id] = {
            "Id": ou_id,
            "Arn": (
                f"arn:aws:organizations::{self.master_account_id}:ou/"
                f"{self.org_id}/{ou_id}",
            ),
            "Name": name,
        }

    def add_delegated_admin(
        self,
        account_id: str,
        service_principal: str,
        delegation_enabled_date: datetime | None = None,
    ):
        self.delegated_admins[account_id].append(
            {
                "Id": account_id,
                "ServicePrincipal": service_principal,
                "DelegationEnabledDate": delegation_enabled_date or datetime.now(),
                "Arn": (
                    f"arn:aws:organizations::{self.master_account_id}:account/"
                    f"{self.org_id}/{account_id}"
                ),
            }
        )
