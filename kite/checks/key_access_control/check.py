"""Check for KMS key access control."""

from typing import Any

from kite.config import Config
from kite.data import get_customer_managed_policies
from kite.data import get_iam_groups
from kite.data import get_iam_users
from kite.data import get_inline_policy_document
from kite.data import get_kms_keys
from kite.data import get_policy_document
from kite.data import get_roles
from kite.helpers import get_account_ids_in_scope
from kite.helpers import manual_check

CHECK_ID = "key-access-control"
CHECK_NAME = "Key Access Control"


def _has_kms_permissions(policy_doc: dict[str, Any]) -> bool:
    """
    Check if a policy document contains KMS permissions.

    Args:
        policy_doc: The policy document to check

    Returns:
        bool: True if the policy contains KMS permissions
    """
    if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
        return False

    statements = policy_doc["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            if action.startswith("kms:") or action == "*":
                return True

    return False


def _has_broad_kms_resource(policy_doc: dict[str, Any]) -> bool:
    """
    Check if a policy document contains broad KMS resource patterns.

    Args:
        policy_doc: The policy document to check

    Returns:
        bool: True if the policy contains broad KMS resource patterns
    """
    if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
        return False

    statements = policy_doc["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    allowed_broad_actions = {
        "kms:CreateKey",
        "kms:GenerateRandom",
        "kms:ListAliases",
        "kms:ListKeys",
    }

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        for action in actions:
            if not action.startswith("kms:"):
                continue

            # Check if this is an allowed broad action
            if action in allowed_broad_actions:
                continue

            # Check for broad resource patterns
            for resource in resources:
                if resource == "*":
                    return True
                if resource.endswith("/*"):
                    return True

    return False


def _has_key_creation_permissions(policy_doc: dict[str, Any]) -> bool:
    """
    Check if a policy document contains key creation permissions.

    Args:
        policy_doc: The policy document to check

    Returns:
        bool: True if the policy contains key creation permissions
    """
    if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
        return False

    statements = policy_doc["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            if action in ["kms:*", "*", "kms:CreateKey"]:
                return True

    return False


def _has_broad_key_policy_sharing(policy_doc: dict[str, Any]) -> bool:
    """
    Check if a key policy has overly broad sharing with principals.

    Args:
        policy_doc: The key policy document to check

    Returns:
        bool: True if the policy has overly broad sharing
    """
    if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
        return False

    statements = policy_doc["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        if statement.get("Effect") != "Allow":
            continue

        # Check for broad principal patterns
        principal = statement.get("Principal", {})
        if isinstance(principal, dict):
            for principal_type, principal_value in principal.items():
                if principal_type == "AWS":
                    if isinstance(principal_value, list):
                        for value in principal_value:
                            if value == "*" or value.endswith("/*"):
                                # Check if there are restrictive conditions
                                conditions = statement.get("Condition", {})
                                if not conditions:
                                    return True

                                # Check for restrictive conditions
                                has_restrictive_condition = False

                                # Check for kms:CallerAccount condition
                                if "StringEquals" in conditions:
                                    if (
                                        "kms:CallerAccount"
                                        in conditions["StringEquals"]
                                    ):
                                        has_restrictive_condition = True

                                # Check for kms:ViaService condition
                                if "StringEquals" in conditions:
                                    if "kms:ViaService" in conditions["StringEquals"]:
                                        has_restrictive_condition = True

                                # Check for kms:EncryptionContext conditions
                                if "StringEquals" in conditions:
                                    for key in conditions["StringEquals"]:
                                        if key.startswith("kms:EncryptionContext:"):
                                            has_restrictive_condition = True
                                            break

                                if not has_restrictive_condition:
                                    return True
                    elif isinstance(principal_value, str):
                        if principal_value == "*" or principal_value.endswith("/*"):
                            # Check if there are restrictive conditions
                            conditions = statement.get("Condition", {})
                            if not conditions:
                                return True

                            # Check for restrictive conditions
                            has_restrictive_condition = False

                            # Check for kms:CallerAccount condition
                            if "StringEquals" in conditions:
                                if "kms:CallerAccount" in conditions["StringEquals"]:
                                    has_restrictive_condition = True

                            # Check for kms:ViaService condition
                            if "StringEquals" in conditions:
                                if "kms:ViaService" in conditions["StringEquals"]:
                                    has_restrictive_condition = True

                            # Check for kms:EncryptionContext conditions
                            if "StringEquals" in conditions:
                                for key in conditions["StringEquals"]:
                                    if key.startswith("kms:EncryptionContext:"):
                                        has_restrictive_condition = True
                                        break

                            if not has_restrictive_condition:
                                return True

    return False


def check_key_access_control() -> dict[str, Any]:
    """
    Check if KMS key access is tightly controlled through appropriate use of key
    policies and IAM policies.

    This check asks the user to confirm that:
    1. Key policies are used instead of IAM policies where possible
    2. Permission to create keys is limited to necessary principals
    3. KMS permissions in IAM policies are restricted to specific key ARNs
    4. Resource: '*' is only used for appropriate KMS actions
    5. Key policies don't have overly broad sharing with principals

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    # Get all accounts in scope
    account_ids = get_account_ids_in_scope()

    # Track IAM policies with KMS permissions
    kms_policies = []
    # Track principals with key creation permissions
    key_creators = []
    # Track policies with broad resource patterns
    broad_resource_policies = []
    # Track keys with broad policy sharing
    broad_key_policies = []

    # Check each account
    for account_id in account_ids:
        # Get all IAM entities and policies in the account
        users = get_iam_users(account_id)
        groups = get_iam_groups(account_id)
        roles = get_roles(account_id)
        customer_policies = get_customer_managed_policies(account_id)

        # Check customer managed policies
        for policy in customer_policies:
            policy_arn = policy["Arn"]
            policy_doc = get_policy_document(account_id, policy_arn)

            if policy_doc and _has_kms_permissions(policy_doc):
                kms_policies.append(
                    {
                        "account_id": account_id,
                        "policy_name": policy["PolicyName"],
                        "policy_arn": policy_arn,
                        "policy_type": "customer_managed",
                    }
                )

                if _has_broad_kms_resource(policy_doc):
                    broad_resource_policies.append(
                        {
                            "account_id": account_id,
                            "policy_name": policy["PolicyName"],
                            "policy_arn": policy_arn,
                            "policy_type": "customer_managed",
                        }
                    )

        # Check users, groups, and roles
        for entity in users + groups + roles:
            # Check inline policies
            for policy_name in entity.get("InlinePolicyNames", []):
                entity_name = (
                    entity.get("UserName")
                    or entity.get("GroupName")
                    or entity["RoleName"]
                )
                policy_doc = get_inline_policy_document(
                    account_id, entity_name, policy_name
                )

                if policy_doc and _has_kms_permissions(policy_doc):
                    policy_info = {
                        "account_id": account_id,
                        "policy_name": policy_name,
                        "policy_type": "inline",
                    }

                    if "UserName" in entity:
                        policy_info.update(
                            {
                                "user_name": entity["UserName"],
                                "user_arn": entity["Arn"],
                            }
                        )
                    elif "GroupName" in entity:
                        policy_info.update(
                            {
                                "group_name": entity["GroupName"],
                                "group_arn": entity["Arn"],
                            }
                        )
                    else:
                        policy_info.update(
                            {
                                "role_name": entity["RoleName"],
                                "role_arn": entity["Arn"],
                            }
                        )

                    kms_policies.append(policy_info)

                    if _has_broad_kms_resource(policy_doc):
                        broad_resource_policies.append(policy_info)

            # Check if entity has key creation permissions
            has_key_creation = False
            for policy in entity.get("AttachedPolicies", []):
                policy_arn = policy["PolicyArn"]
                # Check customer managed policies
                for customer_policy in customer_policies:
                    if customer_policy["Arn"] == policy_arn:
                        policy_doc = get_policy_document(account_id, policy_arn)
                        if policy_doc and _has_key_creation_permissions(policy_doc):
                            has_key_creation = True
                            break
                    if has_key_creation:
                        break

            # Check inline policies
            if not has_key_creation:
                for policy_name in entity.get("InlinePolicyNames", []):
                    entity_name = (
                        entity.get("UserName")
                        or entity.get("GroupName")
                        or entity["RoleName"]
                    )
                    policy_doc = get_inline_policy_document(
                        account_id, entity_name, policy_name
                    )
                    if policy_doc and _has_key_creation_permissions(policy_doc):
                        has_key_creation = True
                        break

            if has_key_creation:
                creator_info = {
                    "account_id": account_id,
                }

                if "UserName" in entity:
                    creator_info.update(
                        {
                            "user_name": entity["UserName"],
                            "user_arn": entity["Arn"],
                        }
                    )
                elif "GroupName" in entity:
                    creator_info.update(
                        {
                            "group_name": entity["GroupName"],
                            "group_arn": entity["Arn"],
                        }
                    )
                else:
                    creator_info.update(
                        {
                            "role_name": entity["RoleName"],
                            "role_arn": entity["Arn"],
                        }
                    )

                key_creators.append(creator_info)

        # Check KMS keys in each region
        for region in Config.get().active_regions:
            keys = get_kms_keys(account_id, region)
            for key in keys:
                # Only check customer managed keys
                if key.get("Metadata", {}).get("KeyManager") != "CUSTOMER":
                    continue

                # Check key policy for broad sharing
                if _has_broad_key_policy_sharing(key.get("Policy", {})):
                    broad_key_policies.append(
                        {
                            "account_id": account_id,
                            "region": region,
                            "key_id": key["KeyId"],
                            "key_arn": key["KeyArn"],
                            "alias": key.get("AliasName", "No alias"),
                        }
                    )

    # Build message for manual check
    message = "Customer Managed IAM Policies with KMS Permissions:\n\n"
    if kms_policies:
        for policy in kms_policies:
            message += f"Account: {policy['account_id']}\n"
            if "user_name" in policy:
                message += f"User: {policy['user_name']}\n"
                message += f"User ARN: {policy['user_arn']}\n"
            elif "group_name" in policy:
                message += f"Group: {policy['group_name']}\n"
                message += f"Group ARN: {policy['group_arn']}\n"
            elif "role_name" in policy:
                message += f"Role: {policy['role_name']}\n"
                message += f"Role ARN: {policy['role_arn']}\n"
            message += f"Policy Name: {policy['policy_name']}\n"
            if "policy_arn" in policy:
                message += f"Policy ARN: {policy['policy_arn']}\n"
            message += f"Policy Type: {policy['policy_type']}\n\n"
    else:
        message += "No Customer Managed IAM policies found with KMS permissions\n\n"

    message += "Principals with Key Creation Permissions:\n\n"
    if key_creators:
        for creator in key_creators:
            message += f"Account: {creator['account_id']}\n"
            if "user_name" in creator:
                message += f"User: {creator['user_name']}\n"
                message += f"User ARN: {creator['user_arn']}\n"
            elif "group_name" in creator:
                message += f"Group: {creator['group_name']}\n"
                message += f"Group ARN: {creator['group_arn']}\n"
            elif "role_name" in creator:
                message += f"Role: {creator['role_name']}\n"
                message += f"Role ARN: {creator['role_arn']}\n"
            message += "\n"
    else:
        message += "No principals found with key creation permissions\n\n"

    message += "Policies with Broad KMS Resource Patterns:\n\n"
    if broad_resource_policies:
        for policy in broad_resource_policies:
            message += f"Account: {policy['account_id']}\n"
            if "user_name" in policy:
                message += f"User: {policy['user_name']}\n"
                message += f"User ARN: {policy['user_arn']}\n"
            elif "group_name" in policy:
                message += f"Group: {policy['group_name']}\n"
                message += f"Group ARN: {policy['group_arn']}\n"
            elif "role_name" in policy:
                message += f"Role: {policy['role_name']}\n"
                message += f"Role ARN: {policy['role_arn']}\n"
            message += f"Policy Name: {policy['policy_name']}\n"
            if "policy_arn" in policy:
                message += f"Policy ARN: {policy['policy_arn']}\n"
            message += f"Policy Type: {policy['policy_type']}\n\n"
    else:
        message += "No policies found with broad KMS resource patterns\n\n"

    message += "Keys with Broad Policy Sharing:\n\n"
    if broad_key_policies:
        for key in broad_key_policies:
            message += f"Account: {key['account_id']}\n"
            message += f"Region: {key['region']}\n"
            message += f"Key ID: {key['key_id']}\n"
            message += f"Key ARN: {key['key_arn']}\n"
            message += f"Alias: {key['alias']}\n\n"
    else:
        message += "No keys found with broad policy sharing\n\n"

    message += (
        "Please review the above and consider:\n"
        "- Are permissions provided in key policies rather than IAM policies "
        "where possible?\n"
        "- Is permission to create keys limited only to principals who need it?\n"
        "- Are KMS permissions in IAM policies restricted to specific key ARNs?\n"
        "- Is Resource: '*' only used for kms:CreateKey, kms:GenerateRandom, "
        "kms:ListAliases, kms:ListKeys, and custom key store permissions?\n"
        "- Are key policies restricted to specific principals rather than using "
        "broad patterns like '*' or 'arn:aws:iam::*'?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is KMS key access tightly controlled through appropriate use of key "
            "policies and IAM policies?"
        ),
        pass_message=(
            "KMS key access is tightly controlled through appropriate use of key "
            "policies and IAM policies."
        ),
        fail_message=(
            "KMS key access should be tightly controlled through appropriate use "
            "of key policies and IAM policies."
        ),
        default=True,
    )


check_key_access_control._CHECK_ID = CHECK_ID
check_key_access_control._CHECK_NAME = CHECK_NAME
