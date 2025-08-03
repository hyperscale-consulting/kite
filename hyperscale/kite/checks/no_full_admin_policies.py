from collections import defaultdict

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output

customer_attached_policy_check_id = (
    "iam_customer_attached_policy_no_administrative_privileges"
)
aws_attached_policy_check_id = "iam_aws_attached_policy_no_administrative_privileges"
customer_unattached_policy_check_id = (
    "iam_customer_unattached_policy_no_administrative_privileges"
)
inline_policy_check_id = "iam_inline_policy_no_administrative_privileges"


class NoFullAdminPoliciesCheck:
    def __init__(self):
        self.check_id = "no-full-admin-policies"
        self.check_name = "No Administrative Privilege Policies"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that no customer managed policies, inline policies, "
            "or attached AWS managed policies, grant full admin privileges"
        )

    def run(self) -> CheckResult:
        """
        Check if there are any policies with administrative privileges.

        This check uses multiple Prowler check results to identify policies
        that have administrative privileges, including:
        - Customer managed attached policies
        - AWS managed attached policies
        - Customer managed unattached policies
        - Inline policies
        """

        prowler_check_ids = [
            customer_attached_policy_check_id,
            aws_attached_policy_check_id,
            customer_unattached_policy_check_id,
            inline_policy_check_id,
        ]

        # Get all prowler check results
        prowler_results = get_prowler_output()

        # Group failed checks by account and check type
        failed_policies = defaultdict(lambda: defaultdict(list))
        checks_with_findings = set()

        # Process results from each check
        for check_id in prowler_check_ids:
            check_results = prowler_results.get(check_id, [])

            for result in check_results:
                if result.status != "PASS":
                    account_id = result.account_id
                    failed_policies[account_id][check_id].append(
                        {
                            "PolicyName": result.resource_name,
                            "ResourceId": result.resource_uid,
                            "Details": result.resource_details,
                        }
                    )

                    # Track which checks found issues
                    checks_with_findings.add(check_id)

        # Determine the status based on findings
        has_admin_policies = bool(failed_policies)

        # Convert the nested defaultdict to a regular dict
        converted_policies = {}
        for account_id, account_results in failed_policies.items():
            converted_policies[account_id] = dict(account_results)

        if not has_admin_policies:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="No policies with administrative privileges were found.",
            )

        # Create the result message for failed case
        message = "The following policies have administrative privileges:\n\n"

        # Map check IDs to friendly names for display
        check_friendly_names = {
            customer_attached_policy_check_id: "Customer Managed Attached Policies",
            aws_attached_policy_check_id: "AWS Managed Attached Policies",
            customer_unattached_policy_check_id: "Customer Managed Unattached Policies",
            inline_policy_check_id: "Inline Policies",
        }

        # Process results by account
        for account_id, account_results in converted_policies.items():
            message += f"Account {account_id}:\n"

            # Process results by check type
            for check_id, policies in account_results.items():
                check_name = check_friendly_names.get(check_id, check_id)
                message += f"  {check_name}:\n"

                # List each policy with its details
                for policy in policies:
                    message += f"  - {policy['PolicyName']} ({policy['ResourceId']})\n"
                    if policy["Details"]:
                        message += f"    Details: {policy['Details']}\n"

            message += "\n"

        message += "Policies with administrative privileges should be avoided as "
        message += "they grant excessive permissions.\n"
        message += "Consider using more granular permissions that follow the "
        message += "principle of least privilege."

        return CheckResult(status=CheckStatus.FAIL, reason=message)
