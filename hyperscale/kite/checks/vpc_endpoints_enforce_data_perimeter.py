import json

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.conditions import has_principal_org_id_condition
from hyperscale.kite.conditions import has_resource_org_id_condition
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_organization
from hyperscale.kite.data import get_vpc_endpoints
from hyperscale.kite.helpers import get_account_ids_in_scope


class VpcEndpointsEnforceDataPerimeterCheck:
    def __init__(self):
        self.check_id = "vpc-endpoints-enforce-data-perimeter"
        self.check_name = "VPC Endpoints Enforce Data Perimeter Controls"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that all VPC endpoints have the required endpoint "
            "policies for data perimeter controls."
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

        # Get all in-scope accounts
        accounts = get_account_ids_in_scope()

        config = Config.get()
        failing_endpoints: list[dict[str, str]] = []
        for account in accounts:
            # Get VPC endpoints for each account in each region
            for region in config.active_regions:
                vpc_endpoints = get_vpc_endpoints(account, region)
                if not vpc_endpoints:
                    continue

                for endpoint in vpc_endpoints:
                    if "PolicyDocument" not in endpoint:
                        failing_endpoints.append(
                            {
                                "id": endpoint["VpcEndpointId"],
                                "account": account,
                                "region": region,
                                "reason": "No endpoint policy found",
                            }
                        )
                        continue

                    try:
                        policy_doc = json.loads(endpoint["PolicyDocument"])
                    except json.JSONDecodeError:
                        failing_endpoints.append(
                            {
                                "id": endpoint["VpcEndpointId"],
                                "account": account,
                                "region": region,
                                "reason": "Invalid policy document",
                            }
                        )
                        continue

                    has_org_conditions = self._has_required_org_conditions(
                        policy_doc, org_id
                    )

                    if not has_org_conditions:
                        failing_endpoints.append(
                            {
                                "id": endpoint["VpcEndpointId"],
                                "account": account,
                                "region": region,
                                "reason": "Missing required organization conditions",
                            }
                        )

        if not failing_endpoints:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="All VPC endpoints have the required endpoint policies",
            )

        return CheckResult(
            status=CheckStatus.FAIL,
            reason="Some VPC endpoints are missing required endpoint policies",
            details={
                "failing_resources": failing_endpoints,
            },
        )

    def _has_required_org_conditions(self, policy_doc: dict, org_id: str) -> bool:
        """
        Check if a policy has the required organization conditions.

        Args:
            policy_doc: The policy document to check
            org_id: The organization ID to check against

        Returns:
            True if the policy has the required conditions, False otherwise
        """
        if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
            return False

        for statement in policy_doc["Statement"]:
            # Check if this is an Allow statement
            effect = statement.get("Effect")
            if effect != "Allow":
                continue

            # Check for required conditions
            conditions = statement.get("Condition", {})
            if not isinstance(conditions, dict):
                continue

            if has_principal_org_id_condition(
                conditions, org_id
            ) and has_resource_org_id_condition(conditions, org_id):
                return True

        return False
