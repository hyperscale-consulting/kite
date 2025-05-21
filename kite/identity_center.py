"""Identity Center module for Kite."""


def list_identity_center_instances(session) -> list:
    """
    List all instances of Identity Center.

    Args:
        session: The boto3 session to use.

    Returns:
        list: List of Identity Center instances.

    Raises:
        ClientError: If the API call fails.
    """
    sso_client = session.client("sso-admin")
    instances = []
    paginator = sso_client.get_paginator("list_instances")

    for page in paginator.paginate():
        instances.extend(page.get("Instances", []))

    return instances


def list_permission_sets(session, instance_arn: str) -> list:
    """
    List all permission sets.
    """
    sso_client = session.client("sso-admin")
    permission_sets = []
    paginator = sso_client.get_paginator("list_permission_sets")
    for page in paginator.paginate(InstanceArn=instance_arn):
        for permission_set_arn in page["PermissionSets"]:
            permission_set = sso_client.describe_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )["PermissionSet"]

            managed_policies = []
            for policy in sso_client.list_managed_policies_in_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )["AttachedManagedPolicies"]:
                managed_policies.append(policy["Name"])

            try:
                inline_policy = sso_client.get_inline_policy_for_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                )["InlinePolicy"]
            except sso_client.exceptions.ResourceNotFoundException:
                inline_policy = None

            permission_set["managed_policies"] = managed_policies
            permission_set["inline_policy"] = inline_policy

            permission_sets.append(permission_set)

    return permission_sets
