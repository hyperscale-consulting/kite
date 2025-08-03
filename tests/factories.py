import json
from pathlib import Path
from tempfile import TemporaryDirectory

from hyperscale.kite.config import Config
from hyperscale.kite.data import save_organization
from hyperscale.kite.data import save_organization_features
from hyperscale.kite.models import Account
from hyperscale.kite.models import ControlPolicy
from hyperscale.kite.models import DelegatedAdmin
from hyperscale.kite.models import Organization
from hyperscale.kite.models import OrganizationalUnit


def create_organization(
    mgmt_account_id="111111111111",
    root_ou=None,
    organization_id="o-123456789012",
    feature_set="ALL",
):
    root_ou = root_ou or build_ou()
    result = Organization(
        id=organization_id,
        master_account_id=mgmt_account_id,
        arn=f"arn:aws:organizations:::{mgmt_account_id}:organization/{organization_id}",
        feature_set=feature_set,
        root=root_ou,
    )
    save_organization(mgmt_account_id, result)
    return result


def create_organization_with_workload_account(
    mgmt_account_id="111111111111",
    workload_account_id="999999999999",
    organization_id="o-123456789012",
):
    create_organization(
        mgmt_account_id=mgmt_account_id,
        organization_id=organization_id,
        root_ou=build_ou(
            child_ous=[
                build_ou(
                    accounts=[
                        build_account(id=workload_account_id),
                    ]
                )
            ]
        ),
    )


def build_account(
    id="999999999999", mgmt_account_id="111111111111", name="Test account", scps=None
) -> Account:
    return Account(
        id=id,
        name=name,
        arn=f"arn:aws:organizations:::{mgmt_account_id}:account/{id}",
        email="test@example.com",
        status="ACTIVE",
        joined_method="CREATED",
        joined_timestamp="2021-01-01T00:00:00Z",
        scps=scps or [],
    )


def build_ou(
    mgmt_account_id="111111111111",
    ou_id="r-fas3",
    organization_id="o-123456789012",
    name="Root",
    accounts: list[Account] | None = None,
    child_ous: list[OrganizationalUnit] | None = None,
    scps: list[ControlPolicy] | None = None,
    rcps: list[ControlPolicy] | None = None,
) -> OrganizationalUnit:
    accounts = accounts or []
    child_ous = child_ous or []
    scps = scps or [build_full_access_scp()]
    rcps = rcps or []
    return OrganizationalUnit(
        id=ou_id,
        name=name,
        arn=f"arn:aws:organizations:::{mgmt_account_id}:organizational-unit/{organization_id}/{ou_id}",
        accounts=accounts,
        scps=scps,
        rcps=rcps,
        child_ous=child_ous,
    )


def build_allow_all_iam_policy():
    return dict(
        Version="2012-10-17",
        Statement=[
            dict(
                Effect="Allow",
                Action="*",
            )
        ],
        Resource="*",
    )


def build_full_access_scp():
    return build_scp(content=build_allow_all_iam_policy())


def build_scp(
    name="FullAWSAccess",
    description="Full access to every operation",
    content=None,
):
    content = content or build_allow_all_iam_policy()
    return ControlPolicy(
        id=f"p-{name}",
        name=f"{name}",
        description=description,
        arn=f"arn:aws:organizations:::service-control-policy/p-{name}",
        content=json.dumps(content),
        type="SERVICE_CONTROL_POLICY",
    )


def build_rcp(
    name="TestRCP",
    description="Test RCP",
    content=None,
):
    content = content or build_allow_all_iam_policy()
    return ControlPolicy(
        id=f"p-{name}",
        name=f"{name}",
        description=description,
        arn=f"arn:aws:organizations:::resource-control-policy/p-{name}",
        content=json.dumps(content),
        type="RESOURCE_CONTROL_POLICY",
    )


def build_delegated_admin(
    account_id,
    service_principal,
    mgmt_account_id="111111111111",
    account_name="Test account",
    account_email="test@example.com",
):
    return DelegatedAdmin(
        id=account_id,
        arn=f"arn:aws:organizations:::{mgmt_account_id}:account/{account_id}",
        name=account_name,
        email=account_email,
        status="ACTIVE",
        joined_method="CREATED",
        joined_timestamp="2021-01-01T00:00:00Z",
        delegation_enabled_date="2021-01-01T00:00:00Z",
        service_principal=service_principal,
    )


def create_config(
    prowler_output_dir=None,
    data_dir=None,
    mgmt_account_id: str | None = "111111111111",
    account_ids: list[str] | None = None,
    active_regions: list[str] | None = None,
    role_name="KiteAssessor",
    external_id="12345",
):
    if active_regions is None:
        active_regions = ["us-east-1", "eu-west-2"]

    with TemporaryDirectory() as d:
        Config.create(
            management_account_id=mgmt_account_id,
            account_ids=account_ids or [],
            active_regions=active_regions,
            role_name=role_name,
            prowler_output_dir=prowler_output_dir or Path(d) / "prowler",
            data_dir=data_dir or Path(d) / "data",
            external_id=external_id,
        )
        return Config.get()


def create_config_for_org(
    mgmt_account_id="111111111111",
    account_ids=None,
    active_regions=None,
    role_name="KiteAssessor",
    external_id="12345",
):
    create_config(
        mgmt_account_id=mgmt_account_id,
        account_ids=account_ids,
        active_regions=active_regions,
        role_name=role_name,
        external_id=external_id,
    )


def create_config_for_standalone_account(
    account_ids=None,
    active_regions=None,
    role_name="KiteAssessor",
    external_id="12345",
):
    create_config(
        mgmt_account_id=None,
        account_ids=account_ids or ["111111111111"],
        active_regions=active_regions,
        role_name=role_name,
        external_id=external_id,
    )


def create_organization_features(management_account_id, features=None):
    features = features if features is not None else ["RootCredentialsManagement"]
    save_organization_features(
        account_id=management_account_id,
        features=features,
    )


def build_dns_firewall_rule(domain_list_id):
    return {
        "FirewallDomainListId": domain_list_id,
        "Name": "allow-domains",
        "Priority": 1,
        "Action": "ALLOW",
        "CreatorRequestId": "AWSConsole.86.1743690407429",
        "CreationTime": "2025-04-03T14:26:47.544157305Z",
        "ModificationTime": "2025-05-09T12:04:54.718779748Z",
        "FirewallDomainRedirectionAction": "TRUST_REDIRECTION_DOMAIN",
    }


def build_dns_firewall_rule_group_association(
    vpc_id, rule_group_id, id="1234567890rga"
):
    return {
        "Id": id,
        "Arn": (
            f"arn:aws:route53resolver:us-west-2:111111111111:firewall-rule-group-association/{id}",
        ),
        "FirewallRuleGroupId": rule_group_id,
        "VpcId": vpc_id,
        "Name": "rgassoc-vpc-57696132-rslvr-frg-f542b8e995bc47",
        "Priority": 101,
        "MutationProtection": "DISABLED",
        "Status": "COMPLETE",
        "StatusMessage": "Finished rule group association update",
        "CreatorRequestId": "AWSConsole.0.1743693525195",
        "CreationTime": "2025-04-03T15:18:45.590591275Z",
        "ModificationTime": "2025-04-03T15:19:37.858904437Z",
    }


def build_dns_firewall_domain_list(id: str, name="foo_domain_list"):
    return {
        "Id": id,
        "Arn": (
            f"arn:aws:route53resolver:us-west-2:111111111111:firewall-domain-list/{id}"
        ),
        "Name": name,
        "CreatorRequestId": "AWSConsole.31.1743690406950",
        "Domains": [],
    }


def build_dns_firewall_rule_group(id: str, name="foo-vpc-rules", rules=None):
    return {
        "Id": id,
        "Arn": (
            f"arn:aws:route53resolver:us-west-2:111111111111:firewall-rule-group/{id}"
        ),
        "Name": name,
        "OwnerId": "111111111111",
        "CreatorRequestId": "AWSConsole.5.1743689990235",
        "ShareStatus": "NOT_SHARED",
        "FirewallRules": rules or [],
    }


def build_prowler_check_result(check_id, account_id, region, status):
    result = [""] * 26
    result[10] = check_id
    result[2] = account_id
    result[25] = region
    result[13] = status
    return ";".join(result) + "\n"


def create_prowler_output_file(account_id, check_results, timestamp="20250624122816"):
    config = Config.get()
    file_path = (
        config.prowler_output_dir / f"prowler-output-{account_id}-{timestamp}.csv"
    )
    config.prowler_output_dir.mkdir(parents=True, exist_ok=True)
    content = [
        "header",
    ]
    content.extend(check_results)
    file_path.write_text("\n".join(content) + "\n")
