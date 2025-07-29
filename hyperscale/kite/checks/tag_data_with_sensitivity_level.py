from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_organization


class TagDataWithSensitivityLevelCheck:
    def __init__(self):
        self.check_id = "tag-data-with-sensitivity-level"
        self.check_name = "Tag Data with Sensitivity Level"

    @property
    def question(self) -> str:
        return (
            "Is resource and data-level tagging used to label data with its "
            "sensitivity level to aid compliance, monitoring and incident response?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that resource and data-level tagging is used to "
            "label data with its sensitivity level."
        )

    def run(self) -> CheckResult:
        # Get organization data
        org = get_organization()
        tag_policies = self._get_tag_policies(org)

        # Format the message with the findings
        message = (
            "Tagging should be used for:\n"
            "- Compliance monitoring\n"
            "- Incident response\n\n"
        )

        if tag_policies:
            message += "The following tag policies were found in the organization:\n"
            for policy in tag_policies:
                message += f"- Name: {policy['name']}\n"
                message += f"  Target: {policy['target']}\n"
                if policy["description"]:
                    message += f"  Description: {policy['description']}\n"
            message += "\n"

        message += (
            "Consider the following factors:\n"
            "- Is tagging consistently applied across all resources?\n"
            "- Are sensitivity levels aligned with the data classification scheme?\n"
            "- Is there a process to maintain and validate tags?"
        )

        return CheckResult(status=CheckStatus.MANUAL, context=message)

    def _get_tag_policies(self, org) -> list[dict[str, str]]:
        """
        Get all tag policies in the organization.

        Args:
            org: The organization object

        Returns:
            List of dictionaries containing tag policy information
        """
        tag_policies = []

        def process_ou(ou):
            # Add tag policies from this OU
            for policy in ou.tag_policies:
                tag_policies.append(
                    {
                        "name": policy.name,
                        "description": policy.description,
                        "target": f"OU: {ou.name}",
                        "content": policy.content,
                    }
                )

            # Process child OUs
            for child_ou in ou.child_ous:
                process_ou(child_ou)

            # Process accounts in this OU
            for account in ou.accounts:
                for policy in account.tag_policies:
                    tag_policies.append(
                        {
                            "name": policy.name,
                            "description": policy.description,
                            "target": f"Account: {account.name}",
                            "content": policy.content,
                        }
                    )

        if org:
            process_ou(org.root)
        return tag_policies
