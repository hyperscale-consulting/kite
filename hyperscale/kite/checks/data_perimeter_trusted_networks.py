import json

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.conditions import has_not_principal_arn_condition
from hyperscale.kite.conditions import has_not_source_ip_condition
from hyperscale.kite.conditions import has_not_source_vpc_condition
from hyperscale.kite.data import get_organization


class DataPerimeterTrustedNetworksCheck:
    def __init__(self):
        self.check_id = "data-perimeter-trusted-networks"
        self.check_name = "Data Perimeter Enforces Trusted Networks"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is at least one SCP and one RCP at the "
            "root or top-level OUs with a Deny effect and at least one of: "
            "NotIpAddressIfExists for aws:SourceIp, StringNotEqualsIfExists for "
            "aws:SourceVpc, or ArnNotLikeIfExists for aws:PrincipalArn."
        )

    def _has_required_conditions(self, policy_content: str) -> bool:
        policy_doc = json.loads(policy_content)
        if "Statement" not in policy_doc:
            return False
        for statement in policy_doc["Statement"]:
            effect = statement.get("Effect")
            if effect != "Deny":
                continue
            conditions = statement.get("Condition", {})
            if not isinstance(conditions, dict):
                continue
            if has_not_source_ip_condition(conditions):
                return True
            if has_not_source_vpc_condition(conditions):
                return True
            if has_not_principal_arn_condition(conditions):
                return True
        return False

    def run(self) -> CheckResult:
        org = get_organization()
        if not org:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="AWS Organizations is not being used",
            )
        root = org.root
        top_level_ous = root.child_ous
        has_scp_controls = False
        failing_scps = []
        root_scps = root.scps
        for scp in root_scps:
            if self._has_required_conditions(scp.content):
                has_scp_controls = True
                break
            else:
                failing_scps.append(
                    {
                        "id": scp.id,
                        "type": "SCP",
                        "target": "Root",
                        "reason": "Missing required trusted network conditions",
                    }
                )
        if not has_scp_controls:
            for ou in top_level_ous:
                for scp in ou.scps:
                    if self._has_required_conditions(scp.content):
                        has_scp_controls = True
                        break
                    else:
                        failing_scps.append(
                            {
                                "id": scp.id,
                                "type": "SCP",
                                "target": ou.name,
                                "reason": "Missing required trusted network conditions",
                            }
                        )
                if has_scp_controls:
                    break
        has_rcp_controls = False
        failing_rcps = []
        root_rcps = root.rcps
        for rcp in root_rcps:
            if self._has_required_conditions(rcp.content):
                has_rcp_controls = True
                break
            else:
                failing_rcps.append(
                    {
                        "id": rcp.id,
                        "type": "RCP",
                        "target": "Root",
                        "reason": "Missing required trusted network conditions",
                    }
                )
        if not has_rcp_controls:
            for ou in top_level_ous:
                for rcp in ou.rcps:
                    if self._has_required_conditions(rcp.content):
                        has_rcp_controls = True
                        break
                    else:
                        failing_rcps.append(
                            {
                                "id": rcp.id,
                                "type": "RCP",
                                "target": ou.name,
                                "reason": "Missing required trusted network conditions",
                            }
                        )
                if has_rcp_controls:
                    break
        if has_scp_controls and has_rcp_controls:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="Data perimeter trusted network controls are enforced by both "
                "SCPs and RCPs",
            )
        failing_resources = failing_scps + failing_rcps
        return CheckResult(
            status=CheckStatus.FAIL,
            reason="Data perimeter trusted network controls are not enforced by both "
            "SCPs and RCPs",
            details={
                "failing_resources": failing_resources,
            },
        )
