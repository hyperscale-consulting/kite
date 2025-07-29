from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_customer_managed_policies
from hyperscale.kite.data import get_iam_groups
from hyperscale.kite.data import get_iam_users
from hyperscale.kite.data import get_kms_keys
from hyperscale.kite.data import get_roles
from hyperscale.kite.helpers import get_account_ids_in_scope


class KeyAccessControlCheck:
    def __init__(self):
        self.check_id = "key-access-control"
        self.check_name = "Key Access Control"

    @property
    def question(self) -> str:
        return (
            "Is KMS key access tightly controlled through appropriate use of key "
            "policies and IAM policies?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that KMS key access is tightly controlled through "
            "appropriate use of key policies and IAM policies."
        )

    def _has_kms_permissions(self, policy_doc: dict) -> bool:
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

    def _has_broad_kms_resource(self, policy_doc: dict) -> bool:
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
                if action in allowed_broad_actions:
                    continue
                for resource in resources:
                    if resource == "*" or resource.endswith("/*"):
                        return True
        return False

    def _has_key_creation_permissions(self, policy_doc: dict) -> bool:
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

    def _has_broad_key_policy_sharing(self, policy_doc: dict) -> bool:
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
            principal = statement.get("Principal", {})
            if isinstance(principal, dict):
                for principal_type, principal_value in principal.items():
                    if principal_type == "AWS":
                        if isinstance(principal_value, list):
                            for value in principal_value:
                                if value == "*" or value.endswith("/*"):
                                    conditions = statement.get("Condition", {})
                                    if not conditions:
                                        return True
                                    has_restrictive_condition = False
                                    if "StringEquals" in conditions:
                                        if (
                                            "kms:CallerAccount"
                                            in conditions["StringEquals"]
                                        ):
                                            has_restrictive_condition = True
                                    if "StringEquals" in conditions:
                                        if (
                                            "kms:ViaService"
                                            in conditions["StringEquals"]
                                        ):
                                            has_restrictive_condition = True
                                    if "StringEquals" in conditions:
                                        for key in conditions["StringEquals"]:
                                            if key.startswith("kms:EncryptionContext:"):
                                                has_restrictive_condition = True
                                                break
                                    if not has_restrictive_condition:
                                        return True
                        elif isinstance(principal_value, str):
                            if principal_value == "*" or principal_value.endswith("/*"):
                                conditions = statement.get("Condition", {})
                                if not conditions:
                                    return True
                                has_restrictive_condition = False
                                if "StringEquals" in conditions:
                                    if (
                                        "kms:CallerAccount"
                                        in conditions["StringEquals"]
                                    ):
                                        has_restrictive_condition = True
                                if "StringEquals" in conditions:
                                    if "kms:ViaService" in conditions["StringEquals"]:
                                        has_restrictive_condition = True
                                if "StringEquals" in conditions:
                                    for key in conditions["StringEquals"]:
                                        if key.startswith("kms:EncryptionContext:"):
                                            has_restrictive_condition = True
                                            break
                                if not has_restrictive_condition:
                                    return True
        return False

    def run(self) -> CheckResult:
        account_ids = get_account_ids_in_scope()
        kms_policies = []
        key_creators = []
        broad_resource_policies = []
        broad_key_policies = []
        for account_id in account_ids:
            users = get_iam_users(account_id)
            groups = get_iam_groups(account_id)
            roles = get_roles(account_id)
            customer_policies = get_customer_managed_policies(account_id)
            for policy in customer_policies:
                policy_arn = policy["Arn"]
                policy_doc = policy["PolicyDocument"]
                if policy_doc and self._has_kms_permissions(policy_doc):
                    kms_policies.append(
                        {
                            "account_id": account_id,
                            "policy_name": policy["PolicyName"],
                            "policy_arn": policy_arn,
                            "policy_type": "customer_managed",
                        }
                    )
                    if self._has_broad_kms_resource(policy_doc):
                        broad_resource_policies.append(
                            {
                                "account_id": account_id,
                                "policy_name": policy["PolicyName"],
                                "policy_arn": policy_arn,
                                "policy_type": "customer_managed",
                            }
                        )
            for entity in users + groups + roles:
                for policy in entity.get("InlinePolicies", []):
                    policy_doc = policy["PolicyDocument"]
                    if policy_doc and self._has_kms_permissions(policy_doc):
                        policy_info = {
                            "account_id": account_id,
                            "policy_name": policy["PolicyName"],
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
                        if self._has_broad_kms_resource(policy_doc):
                            broad_resource_policies.append(policy_info)
                has_key_creation = False
                for policy in entity.get("AttachedPolicies", []):
                    policy_arn = policy["PolicyArn"]
                    for customer_policy in customer_policies:
                        if customer_policy["Arn"] == policy_arn:
                            policy_doc = customer_policy["PolicyDocument"]
                            if policy_doc and self._has_key_creation_permissions(
                                policy_doc
                            ):
                                has_key_creation = True
                                break
                    if has_key_creation:
                        break
                if not has_key_creation:
                    for policy in entity.get("InlinePolicies", []):
                        policy_doc = policy["PolicyDocument"]
                        if policy_doc and self._has_key_creation_permissions(
                            policy_doc
                        ):
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
            for region in Config.get().active_regions:
                keys = get_kms_keys(account_id, region)
                for key in keys:
                    if key.get("Metadata", {}).get("KeyManager") != "CUSTOMER":
                        continue
                    if self._has_broad_key_policy_sharing(key.get("Policy", {})):
                        broad_key_policies.append(
                            {
                                "account_id": account_id,
                                "region": region,
                                "key_id": key["KeyId"],
                                "key_arn": key["KeyArn"],
                                "alias": key.get("AliasName", "No alias"),
                            }
                        )
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
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
