import json

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.conditions import has_not_principal_org_id_condition
from hyperscale.kite.conditions import has_principal_is_not_aws_service_condition
from hyperscale.kite.data import get_organization
from hyperscale.kite.models import ControlPolicy


class DataPerimeterTrustedIdentitiesCheck:
    def __init__(self):
        self.check_id = "data-perimeter-trusted-identities"
        self.check_name = "Data Perimeter Enforces Trusted Identities"

    @property
    def question(self) -> str:
        return ""

    @property
    def description(self) -> str:
        return (
            "This check verifies that either the root OU or all top-level OUs have a "
            "Resource Control Policy (RCP) that prevents service-based access to data "
            "services unless it comes from within the AWS organization."
        )

    def run(self) -> CheckResult:
        # Get organization data
        org = get_organization()
        if not org:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="AWS Organizations is not being used",
            )

        # Get organization ID from the Organization model
        org_id = org.id

        # Check if root OU has the required RCP
        root_has_protection = any(
            self._has_data_perimeter_trusted_identities(rcp, org_id)
            for rcp in org.root.rcps
        )

        if root_has_protection:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "Data perimeter trusted identities protection is attached to the "
                    "root OU"
                ),
            )

        # Check if all top-level OUs have the required RCP
        if not org.root.child_ous:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "Data perimeter trusted identities protection is not attached to "
                    "the root OU and there are no top-level OUs"
                ),
            )

        missing_ous = []
        for ou in org.root.child_ous:
            has_protection = any(
                self._has_data_perimeter_trusted_identities(rcp, org_id)
                for rcp in ou.rcps
            )
            if not has_protection:
                missing_ous.append(ou.name)

        if not missing_ous:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "Data perimeter trusted identities protection is attached to all "
                    "top-level OUs"
                ),
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                "Data perimeter trusted identities protection is not attached to the "
                "root OU or all top-level OUs. Missing protection in OUs: "
                f"{', '.join(missing_ous)}"
            ),
        )

    def _has_data_perimeter_trusted_identities(
        self, policy: ControlPolicy, org_id: str
    ) -> bool:
        """
        Check if a policy has the required data perimeter trusted identities protection.

        Args:
            policy: The policy to check
            org_id: The organization ID to check against

        Returns:
            True if the policy has the required protection, False otherwise
        """
        try:
            policy_doc = json.loads(policy.content)
        except json.JSONDecodeError:
            return False

        if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
            return False

        for statement in policy_doc["Statement"]:
            # Check if this is a Deny statement with the required actions
            effect = statement.get("Effect")
            actions = statement.get("Action", [])
            principal = statement.get("Principal")
            resource = statement.get("Resource")

            required_actions = {
                "s3:*",
                "sqs:*",
                "kms:*",
                "secretsmanager:*",
                "sts:AssumeRole",
                "sts:DecodeAuthorizationMessage",
                "sts:GetAccessKeyInfo",
                "sts:GetFederationToken",
                "sts:GetServiceBearerToken",
                "sts:GetSessionToken",
                "sts:SetContext",
            }

            if (
                effect != "Deny"
                or not all(action in actions for action in required_actions)
                or principal != "*"
                or resource != "*"
            ):
                continue

            # Check for required conditions
            conditions = statement.get("Condition", {})
            if not isinstance(conditions, dict):
                continue

            # Check for required conditions using case-insensitive functions
            if not has_not_principal_org_id_condition(conditions, org_id):
                continue

            if not has_principal_is_not_aws_service_condition(conditions):
                continue

            return True

        return False
