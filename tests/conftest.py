import json
import os
import shutil
from collections import defaultdict
from pathlib import Path

import pytest

from hyperscale.kite.config import Config
from hyperscale.kite.data import save_organization
from hyperscale.kite.models import Account
from hyperscale.kite.models import ControlPolicy
from hyperscale.kite.models import Organization
from hyperscale.kite.models import OrganizationalUnit


class StubSession:
    def __init__(self):
        self.clients = defaultdict(dict)

    def client(self, service_name, region_name=None):
        return self.clients[region_name][service_name]

    def register_client(self, client, service_name, region_name=None):
        self.clients[region_name][service_name] = client


@pytest.fixture
def stub_aws_session():
    yield StubSession()


@pytest.fixture
def mgmt_account_id():
    return "111111111111"


@pytest.fixture
def active_regions():
    return ["us-east-1", "us-west-2", "eu-west-2"]


@pytest.fixture
def role_name():
    return "KiteAssessor"


@pytest.fixture
def prowler_output_dir(tmp_path: Path):
    path = tmp_path / "prowler/output"
    path.mkdir(parents=True, exist_ok=True)
    yield path


@pytest.fixture
def data_dir():
    return "tests/data/audit"


@pytest.fixture(autouse=True)
def config(mgmt_account_id, active_regions, role_name, prowler_output_dir, data_dir):
    # We want an empty data directory for each test
    if os.path.exists(data_dir):
        shutil.rmtree(data_dir)

    Config.create(
        management_account_id=mgmt_account_id,
        account_ids=[],
        active_regions=active_regions,
        role_name=role_name,
        prowler_output_dir=prowler_output_dir,
        data_dir=data_dir,
        external_id="123456",
    )
    return Config.get()


@pytest.fixture
def full_access_scp():
    return ControlPolicy(
        id="p-FullAccess",
        name="FullAWSAccess",
        description="Full access to every operation",
        arn="arn:aws:organizations:::service-control-policy/p-FullAccess",
        content=json.dumps(
            dict(
                Version="2012-10-17",
                Statement=[
                    dict(
                        Effect="Allow",
                        Action="*",
                    )
                ],
                Resource="*",
            )
        ),
        type="SERVICE_CONTROL_POLICY",
    )


@pytest.fixture
def mgmt_account(mgmt_account_id, full_access_scp):
    return Account(
        id=mgmt_account_id,
        name="Management Account",
        arn=f"arn:aws:organizations:::{mgmt_account_id}:account",
        email="management@example.com",
        status="ACTIVE",
        joined_method="CREATED",
        joined_timestamp="2021-01-01T00:00:00Z",
        scps=[
            full_access_scp,
        ],
    )


@pytest.fixture
def audit_account_id():
    return "222222222222"


@pytest.fixture
def audit_account(mgmt_account_id, full_access_scp, audit_account_id):
    return Account(
        id=audit_account_id,
        name="Audit Account",
        arn=f"arn:aws:organizations:::{mgmt_account_id}:account",
        email="audit@example.com",
        status="ACTIVE",
        joined_method="CREATED",
        joined_timestamp="2021-01-01T00:00:00Z",
        scps=[
            full_access_scp,
        ],
    )


@pytest.fixture
def log_account_id():
    return "333333333333"


@pytest.fixture
def log_account(mgmt_account_id, full_access_scp, log_account_id):
    return Account(
        id=log_account_id,
        name="Log Account",
        arn=f"arn:aws:organizations:::{mgmt_account_id}:account",
        email="log@example.com",
        status="ACTIVE",
        joined_method="CREATED",
        joined_timestamp="2021-01-01T00:00:00Z",
        scps=[
            full_access_scp,
        ],
    )


@pytest.fixture
def security_ou(
    mgmt_account, organization_id, audit_account, log_account, full_access_scp
):
    ou_id = "ou-999999999999"
    return OrganizationalUnit(
        id=ou_id,
        name="Security",
        arn=f"arn:aws:organizations:::{mgmt_account.id}:organizational-unit/{organization_id}/{ou_id}",
        accounts=[
            audit_account,
            log_account,
        ],
        child_ous=[],
        scps=[
            full_access_scp,
        ],
    )


@pytest.fixture
def workload_account_id():
    return "444444444444"


@pytest.fixture
def workload_account(mgmt_account_id, full_access_scp, workload_account_id):
    return Account(
        id=workload_account_id,
        name="Workload Account",
        arn=f"arn:aws:organizations:::{mgmt_account_id}:account",
        email="workload@example.com",
        status="ACTIVE",
        joined_method="CREATED",
        joined_timestamp="2021-01-01T00:00:00Z",
        scps=[
            full_access_scp,
        ],
    )


@pytest.fixture
def workloads_ou(mgmt_account, organization_id, workload_account, full_access_scp):
    ou_id = "ou-999999999999"
    return OrganizationalUnit(
        id=ou_id,
        name="Workloads",
        arn=f"arn:aws:organizations:::{mgmt_account.id}:organizational-unit/{organization_id}/{ou_id}",
        accounts=[
            workload_account,
        ],
        child_ous=[],
        scps=[
            full_access_scp,
        ],
    )


@pytest.fixture
def root_ou(mgmt_account, security_ou, workloads_ou, organization_id, full_access_scp):
    ou_id = "r-fas3"
    return OrganizationalUnit(
        id=ou_id,
        name="Root",
        arn=f"arn:aws:organizations:::{mgmt_account.id}:organizational-unit/{organization_id}/{ou_id}",
        accounts=[mgmt_account],
        scps=[
            full_access_scp,
        ],
        child_ous=[
            security_ou,
            workloads_ou,
        ],
    )


@pytest.fixture
def organization_id():
    return "o-123456789012"


@pytest.fixture
def organization(mgmt_account_id, root_ou, organization_id):
    result = Organization(
        id=organization_id,
        master_account_id=mgmt_account_id,
        arn=f"arn:aws:organizations:::{mgmt_account_id}:organization/{organization_id}",
        feature_set="ALL",
        root=root_ou,
    )
    save_organization(mgmt_account_id, result)
    return result
