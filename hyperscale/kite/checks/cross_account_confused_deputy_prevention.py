from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization
from hyperscale.kite.data import get_roles
from hyperscale.kite.helpers import get_account_ids_in_scope


class CrossAccountConfusedDeputyPreventionCheck:
    def __init__(self):
        self.check_id = "cross-account-confused-deputy-prevention"
        self.check_name = "Cross-Account Confused Deputy Prevention"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that any IAM role that can be assumed by principals "
            "from other accounts has the sts:ExternalId condition in its trust policy. "
            "This helps prevent confused deputy attacks by requiring an external ID "
            "that must be known by both the trusting and trusted accounts."
        )

    def _is_principal_in_organization(
        self, principal: str, org_account_ids: set[str]
    ) -> bool:
        if principal.endswith(".amazonaws.com"):
            return True
        try:
            account_id = principal.split(":")[4]
            return account_id in org_account_ids
        except (IndexError, AttributeError):
            return False

    def _has_external_id_condition(self, statement: dict) -> bool:
        conditions = statement.get("Condition", {})
        return (
            "StringEquals" in conditions
            and "sts:ExternalId" in conditions["StringEquals"]
        )

    def run(self) -> CheckResult:
        failing_resources = []
        org = get_organization()
        org_account_ids = set()
        if org:
            org_account_ids = {account.id for account in org.get_accounts()}
        for account_id in get_account_ids_in_scope():
            roles = get_roles(account_id)
            for role in roles:
                has_external_principal = False
                has_external_id_condition = False
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
                if has_external_principal and not has_external_id_condition:
                    failing_resources.append(
                        {
                            "account_id": account_id,
                            "resource_uid": role["RoleId"],
                            "resource_name": role["RoleName"],
                            "resource_details": (
                                "Role can be assumed by principals from other accounts "
                                "without the sts:ExternalId condition"
                            ),
                            "region": "global",
                            "status": "FAIL",
                        }
                    )
        passed = len(failing_resources) == 0
        if passed:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="All cross-account role assumptions have the sts:ExternalId "
                "condition.",
                details={
                    "failing_resources": [],
                },
            )
        else:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    f"Found {len(failing_resources)} roles that can be assumed by "
                    "principals from other accounts without the sts:ExternalId "
                    "condition."
                ),
                details={
                    "failing_resources": failing_resources,
                },
            )
