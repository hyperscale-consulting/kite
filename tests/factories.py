import json
from functools import wraps
from pathlib import Path
from tempfile import TemporaryDirectory

from kite.config import Config
from kite.data import save_organization
from kite.models import Account
from kite.models import ControlPolicy
from kite.models import DelegatedAdmin
from kite.models import Organization
from kite.models import OrganizationalUnit


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


def build_account(
    id="999999999999", mgmt_account_id="111111111111", name="Test account", scps=None
):
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
    accounts=None,
    child_ous=None,
    scps=None,
):
    accounts = accounts or []
    child_ous = child_ous or []
    scps = scps or [build_full_access_scp()]
    return OrganizationalUnit(
        id=ou_id,
        name=name,
        arn=f"arn:aws:organizations:::{mgmt_account_id}:organizational-unit/{organization_id}/{ou_id}",
        accounts=accounts,
        scps=scps,
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
    prowler_output_dir,
    data_dir,
    mgmt_account_id="111111111111",
    account_ids=None,
    active_regions=None,
    role_name="KiteAssessor",
    external_id="12345",
):
    Config.create(
        management_account_id=mgmt_account_id,
        account_ids=account_ids or [],
        active_regions=active_regions or ["us-east-1", "eu-west-2"],
        role_name=role_name,
        prowler_output_dir=prowler_output_dir,
        data_dir=data_dir,
        external_id=external_id,
    )
    return Config.get()


def config(
    mgmt_account_id="111111111111",
    account_ids=None,
    active_regions=None,
    role_name="KiteAssessor",
    external_id="12345",
):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with TemporaryDirectory() as d:
                create_config(
                    mgmt_account_id=mgmt_account_id,
                    account_ids=account_ids,
                    active_regions=active_regions,
                    role_name=role_name,
                    external_id=external_id,
                    prowler_output_dir=Path(d) / "prowler",
                    data_dir=Path(d) / "data",
                )
                return func(*args, **kwargs)

        return wrapper

    return decorator
