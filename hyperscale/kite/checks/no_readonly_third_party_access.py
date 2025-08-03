from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization
from hyperscale.kite.data import get_roles
from hyperscale.kite.prowler import get_prowler_output


class NoReadonlyThirdPartyAccessCheck:
    def __init__(self):
        self.check_id = "no-readonly-third-party-access"
        self.check_name = "No Readonly Third Party Access"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that IAM roles do not have cross-account readonly "
            "access policies. For granting access to 3rd party vendorsr, consider "
            "using ViewOnlyAccess or SecurityAudit"
            "iam_role_cross_account_readonlyaccess_policy check."
        )

    def _is_principal_in_organization(
        self, principal: str, org_account_ids: set[str]
    ) -> bool:
        try:
            account_id = principal.split(":")[4]
            return account_id in org_account_ids
        except (IndexError, AttributeError):
            return False

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        check_id = "iam_role_cross_account_readonlyaccess_policy"

        if check_id not in prowler_results:
            return CheckResult(
                CheckStatus.FAIL,
                reason="Prowler check not found - run a prowler scan and configure "
                "kite to use the prowler results.",
            )

        failing_resources = []

        results = prowler_results[check_id]
        org = get_organization()
        if org is None:
            for result in results:
                if result.status != "PASS":
                    failing_resources.append(
                        {
                            "account_id": result.account_id,
                            "resource_uid": result.resource_uid,
                            "resource_name": result.resource_name,
                            "resource_details": result.resource_details,
                            "region": result.region,
                            "status": result.status,
                        }
                    )
        else:
            org_account_ids = {account.id for account in org.get_accounts()}
            for result in results:
                if result.status != "PASS":
                    roles = get_roles(result.account_id)
                    role = next(
                        (r for r in roles if r["RoleId"] == result.resource_uid),
                        None,
                    )
                    if role is None:
                        continue
                    has_external_principal = False
                    for statement in role["AssumeRolePolicyDocument"].get(
                        "Statement", []
                    ):
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
                                                break
                                    elif isinstance(principal_value, str):
                                        if not self._is_principal_in_organization(
                                            principal_value, org_account_ids
                                        ):
                                            has_external_principal = True
                                            break
                    if has_external_principal:
                        failing_resources.append(
                            {
                                "account_id": result.account_id,
                                "resource_uid": result.resource_uid,
                                "resource_name": result.resource_name,
                                "resource_details": (
                                    "Role can be assumed by principals outside the "
                                    "organization"
                                ),
                                "region": result.region,
                                "status": result.status,
                            }
                        )

        passed = len(failing_resources) == 0
        if passed:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="No IAM roles were found with cross-account readonly access "
                "policies.",
            )
        else:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    f"Found {len(failing_resources)} IAM roles with cross-account "
                    "readonly access policies."
                ),
                details={
                    "failing_resources": failing_resources,
                },
            )
