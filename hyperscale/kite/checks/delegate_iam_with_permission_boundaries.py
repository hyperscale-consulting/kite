from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_customer_managed_policies
from hyperscale.kite.data import get_iam_groups
from hyperscale.kite.data import get_iam_users
from hyperscale.kite.data import get_roles
from hyperscale.kite.helpers import get_account_ids_in_scope


class DelegateIamWithPermissionBoundariesCheck:
    def __init__(self):
        self.check_id = "delegate-iam-with-permission-boundaries"
        self.check_name = "Delegate IAM with Permission Boundaries"

    @property
    def question(self) -> str:
        return (
            "Are permission boundaries used to safely delegate IAM administration "
            "to workload teams?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that IAM delegation is done using permission "
            "boundaries, ensuring that policies allowing IAM actions have conditions "
            "on aws:PermissionsBoundary."
        )

    def _has_permission_boundary_condition(self, policy_doc) -> bool:
        if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
            return False
        statements = policy_doc["Statement"]
        if not isinstance(statements, list):
            statements = [statements]
        for statement in statements:
            if not isinstance(statement, dict):
                continue
            condition = statement.get("Condition", {})
            if not isinstance(condition, dict):
                continue
            for condition_type in ["StringEquals", "ArnEquals"]:
                if condition_type in condition:
                    boundary_condition = condition[condition_type].get(
                        "aws:PermissionsBoundary"
                    )
                    if boundary_condition:
                        return True
        return False

    def run(self) -> CheckResult:
        entities_with_delegation = []
        account_ids = get_account_ids_in_scope()
        for account_id in account_ids:
            users = get_iam_users(account_id)
            groups = get_iam_groups(account_id)
            roles = get_roles(account_id)
            customer_policies = get_customer_managed_policies(account_id)
            for entity in users + groups + roles:
                has_iam_delegation = False
                delegation_policy_info = None
                for policy in entity.get("AttachedPolicies", []):
                    policy_arn = policy["PolicyArn"]
                    for customer_policy in customer_policies:
                        if customer_policy["Arn"] == policy_arn:
                            policy_doc = customer_policy["PolicyDocument"]
                            if policy_doc and self._has_permission_boundary_condition(
                                policy_doc
                            ):
                                has_iam_delegation = True
                                delegation_policy_info = {
                                    "policy_name": customer_policy["Name"],
                                    "policy_arn": policy_arn,
                                    "policy_type": "customer_managed",
                                }
                                break
                    if has_iam_delegation:
                        break
                if not has_iam_delegation:
                    for policy in entity.get("InlinePolicies", []):
                        policy_doc = policy["PolicyDocument"]
                        if policy_doc and self._has_permission_boundary_condition(
                            policy_doc
                        ):
                            has_iam_delegation = True
                            delegation_policy_info = {
                                "policy_name": policy["PolicyName"],
                                "policy_type": "inline",
                            }
                            break
                if has_iam_delegation and delegation_policy_info:
                    entities_with_delegation.append(
                        {
                            "account_id": account_id,
                            "entity_name": entity.get("RoleName")
                            or entity.get("UserName")
                            or entity.get("GroupName"),
                            "entity_arn": entity["Arn"],
                            **delegation_policy_info,
                        }
                    )
        if not entities_with_delegation:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "No IAM entities found with IAM delegation policies. "
                    "Permission boundaries should be used to safely delegate IAM "
                    "administration to workload teams."
                ),
            )
        message = "IAM entities with IAM Delegation Policies:\n\n"
        for entity in entities_with_delegation:
            message += f"Account: {entity['account_id']}\n"
            message += f"Entity Name: {entity['entity_name']}\n"
            message += f"Entity ARN: {entity['entity_arn']}\n"
            if "policy_arn" in entity:
                message += f"Policy ARN: {entity['policy_arn']}\n"
            message += f"Policy Name: {entity['policy_name']}\n"
            message += f"Policy Type: {entity['policy_type']}\n\n"
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
