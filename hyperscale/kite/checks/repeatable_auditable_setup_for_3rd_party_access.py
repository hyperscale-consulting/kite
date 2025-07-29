from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization
from hyperscale.kite.data import get_roles
from hyperscale.kite.helpers import get_account_ids_in_scope


class RepeatableAuditableSetupFor3rdPartyAccessCheck:
    def __init__(self):
        self.check_id = "repeatable-auditable-setup-for-3rd-party-access"
        self.check_name = "Repeatable and Auditable Setup for Third-Party Access"

    @property
    def question(self) -> str:
        return (
            "Is there a repeatable and auditable process for setting up access "
            "for third parties?"
        )

    @property
    def description(self) -> str:
        return (
            "This check identifies roles that can be assumed by external principals "
            "with ExternalId conditions and prompts for review of the setup process "
            "to ensure it is repeatable and auditable."
        )

    def _is_principal_in_organization(
        self, principal: str, org_account_ids: set[str]
    ) -> bool:
        """
        Check if a principal is from an account within the organization.

        Args:
            principal: The principal ARN to check
            org_account_ids: Set of account IDs in the organization

        Returns:
            bool: True if the principal is from an account within the organization
        """
        # Service principals are always considered internal
        if principal.endswith(".amazonaws.com"):
            return True

        # Extract account ID from principal ARN
        try:
            account_id = principal.split(":")[4]
            return account_id in org_account_ids
        except (IndexError, AttributeError):
            return False

    def _has_external_id_condition(self, statement: dict) -> bool:
        """
        Check if a statement has the sts:ExternalId condition.

        Args:
            statement: The policy statement to check

        Returns:
            bool: True if the statement has the sts:ExternalId condition
        """
        conditions = statement.get("Condition", {})
        return (
            "StringEquals" in conditions
            and "sts:ExternalId" in conditions["StringEquals"]
        )

    def run(self) -> CheckResult:
        # Track roles that need review
        roles_to_review: list[dict] = []

        # Get organization data
        org = get_organization()
        if org is None:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "AWS Organizations is not being used, so third-party access "
                    "cannot be assessed."
                ),
            )

        org_account_ids = {account.id for account in org.get_accounts()}

        # Check each account
        for account_id in get_account_ids_in_scope():
            # Get all roles in the account
            roles = get_roles(account_id)

            # Check each role's trust policy
            for role in roles:
                has_external_principal = False
                has_external_id_condition = False

                # Check each statement in the trust policy
                for statement in role["AssumeRolePolicyDocument"].get("Statement", []):
                    if statement.get("Effect") == "Allow":
                        principals = statement.get("Principal", {})
                        if isinstance(principals, dict):
                            for _, principal_value in principals.items():
                                if isinstance(principal_value, list):
                                    for principal in principal_value:
                                        if not self._is_principal_in_organization(
                                            principal, org_account_ids
                                        ):
                                            has_external_principal = True
                                            if self._has_external_id_condition(
                                                statement
                                            ):
                                                has_external_id_condition = True
                                            break
                                elif isinstance(principal_value, str):
                                    if not self._is_principal_in_organization(
                                        principal_value, org_account_ids
                                    ):
                                        has_external_principal = True
                                        if self._has_external_id_condition(statement):
                                            has_external_id_condition = True
                                        break

                # If the role can be assumed by external principals and has the
                # sts:ExternalId condition, it needs review
                if has_external_principal and has_external_id_condition:
                    roles_to_review.append(
                        {
                            "account_id": account_id,
                            "resource_uid": role["RoleId"],
                            "resource_name": role["RoleName"],
                            "resource_details": (
                                "Role can be assumed by external principals and has "
                                "the sts:ExternalId condition. Review the setup "
                                "process to ensure it is repeatable and auditable."
                            ),
                            "region": "global",
                            "status": "REVIEW",
                        }
                    )

        if not roles_to_review:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "No roles found that can be assumed by external principals "
                    "with ExternalId conditions."
                ),
            )

        # Build message for manual check
        message = (
            f"Found {len(roles_to_review)} roles that can be assumed by external "
            "principals with ExternalId conditions:\n\n"
        )

        for role in roles_to_review:
            message += f"- {role['resource_name']} in account {role['account_id']}\n"

        message += (
            "\nFor each role, review whether there is a repeatable and auditable "
            "process for setting up access, considering:\n"
            "- Is there prescriptive guidance for creating these roles, in particular "
            "for generating a non-guessable ExternalId?\n"
            "- Is role creation automated (e.g., via CloudFormation)?\n"
            "- Can role configuration be checked for drift as part of ongoing audit?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
