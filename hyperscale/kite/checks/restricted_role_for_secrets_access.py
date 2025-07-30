from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_role_by_arn
from hyperscale.kite.data import get_secrets
from hyperscale.kite.helpers import get_account_ids_in_scope


class RestrictedRoleForSecretsAccessCheck:
    def __init__(self):
        self.check_id = "restricted-role-for-secrets-access"
        self.check_name = "Restricted Role for Secrets Access"

    @property
    def question(self) -> str:
        return (
            "Is human exposure to secrets restricted to a dedicated role that can "
            "only be assumed by a small set of operational users?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that secrets access is restricted to a dedicated "
            "role that can only be assumed by a small set of operational users."
        )

    def run(self) -> CheckResult:
        account_ids = get_account_ids_in_scope()
        config = Config.get()

        secrets_without_policy = []
        secrets_without_deny = []
        principals_found = {}

        for account_id in account_ids:
            for region in config.active_regions:
                secrets = get_secrets(account_id, region)

                for secret in secrets:
                    if not secret.get("ResourcePolicy", {}):
                        secrets_without_policy.append(
                            {
                                "account_id": account_id,
                                "region": region,
                                "secret_name": secret["Name"],
                                "arn": secret["ARN"],
                            }
                        )
                        continue

                    # Parse the resource policy
                    policy = secret.get("ResourcePolicy", {})

                    # Check for deny statements with principal conditions
                    has_principal_deny = False
                    for statement in policy.get("Statement", []):
                        if (
                            statement.get("Effect") == "Deny"
                            and statement.get("Principal") == "*"
                        ):
                            condition = statement.get("Condition", {})
                            for key in [
                                "StringNotEquals",
                                "ArnNotEquals",
                                "StringNotLike",
                                "ArnNotLike",
                            ]:
                                if key in condition:
                                    for value in condition[key].values():
                                        if isinstance(value, list):
                                            for v in value:
                                                principals_found[v] = get_trust_policy(
                                                    v
                                                )
                                        elif isinstance(value, str):
                                            principals_found[value] = get_trust_policy(
                                                value
                                            )
                                    has_principal_deny = True

                    if not has_principal_deny:
                        secrets_without_deny.append(
                            {
                                "account_id": account_id,
                                "region": region,
                                "secret_name": secret["Name"],
                                "arn": secret["ARN"],
                            }
                        )

        # If no secrets found, automatically pass
        if (
            not secrets_without_policy
            and not secrets_without_deny
            and not principals_found
        ):
            return CheckResult(
                status=CheckStatus.PASS,
                reason="No secrets found in in-scope accounts.",
            )

        # Build message for manual review
        message = (
            "Secrets should have resource policies that look something like this, to "
            "ensure that they can only be accessed via a dedicated role:\n\n"
            "{\n"
            '  "Statement": [\n'
            "    {\n"
            '      "Effect": "Allow",\n'
            '      "Principal": {"AWS": "arn:aws:iam::123456789012:role/SecretAdmin"}\n'
            "    },\n"
            "    {\n"
            '      "Effect": "Deny",\n'
            '      "Principal": "*",\n'
            '      "Action": "*",\n'
            '      "Condition": {\n'
            '        "StringNotEquals": {\n'
            '        "  aws:PrincipalArn": "arn:aws:iam::123456789012:role/SecretAdmin"'
            "\n"
            "        }\n"
            "    }\n"
            "  ]\n"
            "}\n\n"
        )
        message += (
            "This role should only be assumable by a small set of operational "
            "users, and monitored for abuse.\n\n"
        )

        if secrets_without_policy:
            message += "Secrets without resource policies:\n"
            for secret in secrets_without_policy:
                message += (
                    f"- {secret['secret_name']} in account {secret['account_id']} "
                    f"region {secret['region']}\n"
                )
            message += "\n"

        if secrets_without_deny:
            message += "Secrets without deny statements:\n"
            for secret in secrets_without_deny:
                message += (
                    f"- {secret['secret_name']} in account {secret['account_id']} "
                    f"region {secret['region']}\n"
                )
            message += "\n"

        if principals_found:
            message += "Principals found in deny exception conditions:\n\n"
            for principal, trust_policy in principals_found.items():
                message += f"- {principal}\n"
                if trust_policy:
                    message += "  Principals allowed to assume this role:\n"
                    message += "\n".join(
                        [
                            f"  - {s['Principal']}"
                            for s in trust_policy.get("Statement", [])
                            if s.get("Effect") == "Allow"
                        ]
                    )
                else:
                    message += "  No trust policy found.\n"
                message += "\n"

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )


def get_trust_policy(role_arn):
    role = get_role_by_arn(role_arn)
    if role:
        return role["AssumeRolePolicyDocument"]
    return None
