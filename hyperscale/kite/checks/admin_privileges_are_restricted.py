from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_customer_managed_policies
from hyperscale.kite.data import get_roles
from hyperscale.kite.data import get_saml_providers
from hyperscale.kite.helpers import get_account_ids_in_scope


class AdminPrivilegesAreRestrictedCheck:
    def __init__(self):
        self.check_id = "admin-privileges-are-restricted"
        self.check_name = "Admin Privileges Are Restricted"

    @property
    def question(self) -> str:
        return "Are administrator privileges restricted to a small, trusted group?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that administrator privileges are restricted to a "
            "small, trusted group."
        )

    def _is_admin_policy(self, policy_doc):
        for statement in policy_doc.get("Statement", []):
            if (
                statement.get("Effect") == "Allow"
                and statement.get("Action") == "*"
                and statement.get("Resource") == "*"
            ):
                return True
        return False

    def _is_service_linked_role(self, role):
        if role.get("Path", "").startswith("/aws-service-role/"):
            return True
        role_name = role.get("RoleName", "")
        if role_name in {
            "aws-controltower-AdministratorExecutionRole",
            "AWSControlTowerExecution",
        }:
            return True
        assume_role_policy = role.get("AssumeRolePolicyDocument", {})
        for statement in assume_role_policy.get("Statement", []):
            principal = statement.get("Principal", {})
            if isinstance(principal, dict):
                aws_principal = principal.get("AWS", "")
                if (
                    isinstance(aws_principal, str)
                    and "/aws-service-role/" in aws_principal
                ):
                    return True
                if isinstance(aws_principal, list):
                    for arn in aws_principal:
                        if isinstance(arn, str) and "/aws-service-role/" in arn:
                            return True
        return False

    def run(self) -> CheckResult:
        saml_providers = []
        admin_roles = []
        config = Config.get()
        if config.management_account_id:
            providers = get_saml_providers(config.management_account_id)
            if providers:
                for provider in providers:
                    saml_providers.append(
                        {
                            "arn": provider["Arn"],
                            "valid_until": provider.get("ValidUntil"),
                            "create_date": provider["CreateDate"],
                        }
                    )
        for account_id in get_account_ids_in_scope():
            roles = get_roles(account_id)
            customer_policies = get_customer_managed_policies(account_id)
            for role in roles:
                if self._is_service_linked_role(role):
                    continue
                has_admin_access = False
                admin_policy_info = None
                for policy in role.get("AttachedPolicies", []):
                    policy_arn = policy["PolicyArn"]
                    if policy_arn.endswith("AdministratorAccess"):
                        has_admin_access = True
                        admin_policy_info = {
                            "policy_name": "AdministratorAccess",
                            "policy_arn": policy_arn,
                            "policy_type": "aws_managed",
                        }
                        break
                    for customer_policy in customer_policies:
                        if customer_policy["Arn"] == policy_arn:
                            policy_doc = customer_policy["PolicyDocument"]
                            if policy_doc and self._is_admin_policy(policy_doc):
                                has_admin_access = True
                                admin_policy_info = {
                                    "policy_name": customer_policy["Name"],
                                    "policy_arn": policy_arn,
                                    "policy_type": "customer_managed",
                                }
                                break
                    if has_admin_access:
                        break
                if not has_admin_access:
                    for policy in role.get("InlinePolicies", []):
                        policy_doc = policy["PolicyDocument"]
                        if policy_doc and self._is_admin_policy(policy_doc):
                            has_admin_access = True
                            admin_policy_info = {
                                "policy_name": policy["PolicyName"],
                                "policy_type": "inline",
                            }
                            break
                if has_admin_access and admin_policy_info:
                    admin_roles.append(
                        {
                            "account_id": account_id,
                            "role_name": role["RoleName"],
                            "role_arn": role["Arn"],
                            **admin_policy_info,
                        }
                    )
        message = "SAML Providers:\n\n"
        if saml_providers:
            for provider in saml_providers:
                message += f"ARN: {provider['arn']}\n"
                if provider.get("valid_until"):
                    message += f"Valid until: {provider['valid_until']}\n"
                message += f"Created: {provider['create_date']}\n\n"
        else:
            message += "No SAML providers configured\n\n"
        message += (
            "Roles with Administrator Privileges (excluding AWS service-linked "
            "roles):\n\n"
        )
        if admin_roles:
            for role in admin_roles:
                message += f"Account: {role['account_id']}\n"
                message += f"Role Name: {role['role_name']}\n"
                message += f"Role ARN: {role['role_arn']}\n"
                if "policy_arn" in role:
                    message += f"Policy ARN: {role['policy_arn']}\n"
                message += f"Policy Name: {role['policy_name']}\n"
                message += f"Policy Type: {role['policy_type']}\n"
                message += "Assume Role Policy:\n"
                role_data = next(
                    (
                        r
                        for r in get_roles(role["account_id"])
                        if r["RoleName"] == role["role_name"]
                    ),
                    None,
                )
                if role_data and "AssumeRolePolicyDocument" in role_data:
                    policy_doc = role_data["AssumeRolePolicyDocument"]
                    for statement in policy_doc.get("Statement", []):
                        message += f"  Effect: {statement.get('Effect', 'N/A')}\n"
                        message += "  Principal:\n"
                        principal = statement.get("Principal", {})
                        if isinstance(principal, dict):
                            for key, value in principal.items():
                                if isinstance(value, list):
                                    for item in value:
                                        message += f"    {key}: {item}\n"
                                else:
                                    message += f"    {key}: {value}\n"
                        message += f"  Action: {statement.get('Action', 'N/A')}\n"
                        if "Condition" in statement:
                            message += "  Condition:\n"
                            for key, value in statement["Condition"].items():
                                message += f"    {key}: {value}\n"
                message += "\n"
        else:
            message += "No roles found with administrator privileges\n\n"
        message += "Consider the SAML providers and roles listed above.\n"
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
            details={
                "saml_providers": saml_providers,
                "admin_roles": admin_roles,
            },
        )
