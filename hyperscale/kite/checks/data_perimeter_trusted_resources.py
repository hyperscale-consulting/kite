import json

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.conditions import has_not_resource_org_id_condition
from hyperscale.kite.data import get_organization
from hyperscale.kite.models import ControlPolicy


class DataPerimeterTrustedResourcesCheck:
    def __init__(self):
        self.check_id = "data-perimeter-trusted-resources"
        self.check_name = "Data Perimeter Enforces Trusted Resources"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that either the root OU or all top-level OUs have a "
            "Service Control Policy (SCP) that enforces trusted resources protection "
            "for data perimeter controls by denying access to resources outside the "
            "AWS organization."
        )

    def _has_data_perimeter_trusted_resources(
        self, policy: ControlPolicy, org_id: str
    ) -> bool:
        try:
            policy_doc = json.loads(policy.content)
        except json.JSONDecodeError:
            return False
        if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
            return False
        for statement in policy_doc["Statement"]:
            effect = statement.get("Effect")
            if effect != "Deny":
                continue
            conditions = statement.get("Condition", {})
            if not isinstance(conditions, dict):
                continue
            if has_not_resource_org_id_condition(conditions, org_id):
                return True
        return False

    def run(self) -> CheckResult:
        org = get_organization()
        if not org:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="AWS Organizations is not being used",
            )
        org_id = org.id
        root_has_protection = any(
            self._has_data_perimeter_trusted_resources(scp, org_id)
            for scp in org.root.scps
        )
        if root_has_protection:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="Data perimeter trusted resources SCP is attached to the root "
                "OU",
            )
        if not org.root.child_ous:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="Data perimeter trusted resources SCP is not attached to the "
                "root OU and there are no top-level OUs",
            )
        missing_ous = []
        for ou in org.root.child_ous:
            has_protection = any(
                self._has_data_perimeter_trusted_resources(scp, org_id)
                for scp in ou.scps
            )
            if not has_protection:
                missing_ous.append(ou.name)
        if not missing_ous:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="Data perimeter trusted resources SCP is attached to all "
                "top-level OUs",
            )
        return CheckResult(
            status=CheckStatus.FAIL,
            reason=(
                "Data perimeter trusted resources SCP is not attached to the root OU "
                "or all top-level OUs. "
                f"Missing protection in OUs: {', '.join(missing_ous)}"
            ),
        )
