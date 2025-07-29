import uuid
from collections import defaultdict

import pytest

from hyperscale.kite.identity_center import get_identity_center_instances


class SsoAdminClient:
    def __init__(self):
        self.instances = []
        self.paginators = {
            "list_instances": ListInstancesPaginator(self.instances),
        }

    def get_paginator(self, operation_name):
        return self.paginators[operation_name]

    def add_instance(self, identity_store_id):
        self.instances.append(
            {
                "InstanceArn": f"arn:aws:sso:::instance/ssoins-{uuid.uuid4()}",
                "IdentityStoreId": identity_store_id,
                "Status": "ACTIVE",
            }
        )


class ListInstancesPaginator:
    def __init__(self, instances):
        self.instances = instances

    def paginate(self):
        return [
            {
                "Instances": self.instances,
            }
        ]


class ListUsersPaginator:
    def __init__(self, users):
        self.users = users

    def paginate(self, IdentityStoreId):
        users = self.users[IdentityStoreId]
        return [
            {
                "Users": users,
            }
        ]


class ListGroupMembershipsForMemberPaginator:
    def __init__(self, group_memberships):
        self.group_memberships = group_memberships

    def paginate(self, IdentityStoreId, MemberId):
        user_id = MemberId["UserId"]
        group_memberships = self.group_memberships[IdentityStoreId][user_id]
        return [
            {
                "GroupMemberships": group_memberships,
            }
        ]


class ListGroupsPaginator:
    def __init__(self, groups):
        self.groups = groups

    def paginate(self, IdentityStoreId):
        groups = self.groups[IdentityStoreId]
        return [
            {
                "Groups": groups,
            }
        ]


class IdentityStoreClient:
    def __init__(self):
        self.users = defaultdict(list)
        self.group_memberships = defaultdict(dict)
        self.groups = defaultdict(list)
        self.paginators = {
            "list_users": ListUsersPaginator(self.users),
            "list_group_memberships_for_member": ListGroupMembershipsForMemberPaginator(
                self.group_memberships
            ),
            "list_groups": ListGroupsPaginator(self.groups),
        }

    def get_paginator(self, operation_name):
        return self.paginators[operation_name]

    def add_user(self, identity_store_id, user_id, user_name, display_name, groups):
        self.users[identity_store_id].append(
            {
                "UserId": user_id,
                "UserName": user_name,
                "DisplayName": display_name,
            }
        )
        self.group_memberships[identity_store_id][user_id] = [
            {
                "IdentityStoreId": identity_store_id,
                "MembershipId": str(uuid.uuid4()),
                "GroupId": group_id,
                "MemberId": {"UserId": user_id},
            }
            for group_id in groups
        ]

    def add_group(self, identity_store_id, group_id, group_name):
        self.groups[identity_store_id].append(
            {
                "GroupId": group_id,
                "DisplayName": group_name,
                "Description": group_name,
            }
        )


@pytest.fixture
def sso_admin_client():
    return SsoAdminClient()


@pytest.fixture
def identity_store_client():
    return IdentityStoreClient()


@pytest.fixture
def session(stub_aws_session, sso_admin_client, identity_store_client):
    stub_aws_session.register_client(sso_admin_client, "sso-admin")
    stub_aws_session.register_client(identity_store_client, "identitystore")
    yield stub_aws_session


def test_list_identity_center_instances_success(
    session, sso_admin_client, identity_store_client
):
    sso_admin_client.add_instance(identity_store_id="d-1234567890")
    sso_admin_client.add_instance(identity_store_id="d-0987654321")

    identity_store_client.add_user(
        identity_store_id="d-1234567890",
        user_id="user-1234567890",
        user_name="test-user-1",
        display_name="Test User 1",
        groups=["group-1234567890", "group-0987654321"],
    )
    identity_store_client.add_user(
        identity_store_id="d-1234567890",
        user_id="user-0987654321",
        user_name="test-user-2",
        display_name="Test User 2",
        groups=["group-1234567890"],
    )

    identity_store_client.add_group(
        identity_store_id="d-1234567890",
        group_id="group-1234567890",
        group_name="Test Group 1",
    )
    identity_store_client.add_group(
        identity_store_id="d-1234567890",
        group_id="group-0987654321",
        group_name="Test Group 2",
    )

    result = get_identity_center_instances(session)

    assert len(result) == 2
    id_store_1 = result[0]
    id_store_2 = result[1]
    assert id_store_1["IdentityStoreId"] == "d-1234567890"

    users = id_store_1["IdentityStoreUsers"]
    assert len(users) == 2
    assert users[0]["UserId"] == "user-1234567890"
    assert users[0]["UserName"] == "test-user-1"
    assert users[0]["DisplayName"] == "Test User 1"
    assert users[1]["UserId"] == "user-0987654321"
    assert users[1]["UserName"] == "test-user-2"
    assert users[1]["DisplayName"] == "Test User 2"

    groups = id_store_1["IdentityStoreGroups"]
    assert len(groups) == 2
    assert groups[0]["GroupId"] == "group-1234567890"
    assert groups[0]["DisplayName"] == "Test Group 1"
    assert groups[1]["GroupId"] == "group-0987654321"

    assert id_store_2["IdentityStoreId"] == "d-0987654321"
    assert len(id_store_2["IdentityStoreUsers"]) == 0
    assert len(id_store_2["IdentityStoreGroups"]) == 0


def test_list_identity_center_instances_empty(session):
    result = get_identity_center_instances(session)
    assert result == []
