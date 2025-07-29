from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.data import get_credentials_report
from hyperscale.kite.helpers import get_account_ids_in_scope


class NoIamUserAccessCheck:
    def __init__(self):
        self.check_id = "no-iam-user-access"
        self.check_name = "No IAM User Access"

    @property
    def question(self) -> str:
        return (
            "Do the instances of IAM user console access represent systematic "
            "use of IAM users rather than federation?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that IAM roles and federated access is used rather "
            "than IAM users, except in exceptional cases such as emergency break-glass "
            "access."
        )

    def run(self) -> CheckResult:
        """
        Check if IAM users are used for console access, rather than federation.

        This check:
        1. Gets credentials reports for all in-scope accounts
        2. Identifies users with console access
        3. If no users with console access exist, automatically passes
        4. If users with console access exist, requires manual review
        """
        # Get in-scope accounts
        account_ids = get_account_ids_in_scope()

        # Get credentials reports for each account
        users_with_console_access = []
        for account_id in account_ids:
            report = get_credentials_report(account_id)
            # Check both root and user accounts
            for user in report["users"]:
                if user.get("password_enabled", "false").lower() == "true":
                    users_with_console_access.append(
                        {
                            "account_id": account_id,
                            "user_name": user["user"],
                        }
                    )

        # If no users with console access found, automatically pass
        if not users_with_console_access:
            return CheckResult(
                status=CheckStatus.PASS,
                reason="No IAM users with console access found in in-scope accounts.",
            )

        # Create message for manual check
        message = (
            "IAM users with console access were found in your in-scope accounts. "
            "Consider the following factors:\n"
            "- Are these instances of systematic use of IAM users for console access?\n"
            "- Or do they represent exceptional scenarios (e.g. emergency access)?\n\n"
            "Users with Console Access:\n"
        )

        # Add user details to message
        for user in users_with_console_access:
            message += f"- User {user['user_name']} in account {user['account_id']}\n"

        return CheckResult(
            status=CheckStatus.MANUAL,
            reason="IAM user console access requires manual review.",
            details={
                "users_with_console_access": users_with_console_access,
            },
            context=message,
        )
