from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.prowler import get_prowler_output


class CredentialRotationCheck:
    def __init__(self):
        self.check_id = "credential-rotation"
        self.check_name = "Credential Rotation"

    @property
    def question(self) -> str:
        return "Are long-term credentials rotated regularly?"

    @property
    def description(self) -> str:
        return (
            "This check verifies that long-term credentials are rotated regularly, "
            "including access keys, KMS keys, and secrets."
        )

    def run(self) -> CheckResult:
        prowler_results = get_prowler_output()
        access_key_results = prowler_results.get("iam_rotate_access_key_90_days", [])
        kms_results = prowler_results.get("kms_cmk_rotation_enabled", [])
        secrets_results = prowler_results.get(
            "secretsmanager_automatic_rotation_enabled", []
        )
        context_message = "Relevant Prowler checks:\n\n"
        found_failures = False
        failed_access_keys = [r for r in access_key_results if r.status == "FAIL"]
        if failed_access_keys:
            found_failures = True
            context_message += "Access Key Rotation (90 days) - Failed Checks:\n"
            for result in failed_access_keys:
                context_message += f"- {result.resource_uid}\n"
            context_message += "\n"
        else:
            context_message += "Access Key Rotation (90 days) - No failures found.\n\n"
        failed_kms_keys = [r for r in kms_results if r.status == "FAIL"]
        if failed_kms_keys:
            found_failures = True
            context_message += "KMS Key Rotation - Failed Checks:\n"
            for result in failed_kms_keys:
                context_message += f"- {result.resource_uid}\n"
            context_message += "\n"
        else:
            context_message += "KMS Key Rotation - No failures found.\n\n"
        failed_secrets = [r for r in secrets_results if r.status == "FAIL"]
        if failed_secrets:
            found_failures = True
            context_message += "Secrets Manager Rotation - Failed Checks:\n"
            for result in failed_secrets:
                context_message += f"- {result.resource_uid}\n"
            context_message += "\n"
        else:
            context_message += "Secrets Manager Rotation - No failures found.\n\n"
        if not found_failures:
            context_message += "All credential rotation checks passed.\n\n"
        context_message += (
            "This check verifies that long-term credentials are rotated regularly.\n\n"
            "Consider the following factors:\n"
            "- Are access keys rotated at least every 90 days?\n"
            "- Are KMS keys rotated annually?\n"
            "- Are secrets rotated automatically?\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context_message,
        )
