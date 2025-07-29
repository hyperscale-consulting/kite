from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class PreventAndDetectSecretsCheck:
    def __init__(self):
        self.check_id = "prevent-and-detect-secrets-in-source-code"
        self.check_name = "Prevent and Detect Secrets in Source Code"

    @property
    def question(self) -> str:
        return (
            "Are there controls in place to prevent and detect secrets in source code?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there are controls in place to prevent and "
            "detect secrets in source code."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are there pre-commit hooks or similar controls to prevent secrets from "
            "being committed?\n"
            "- Are there automated scans in CI/CD pipelines to detect secrets?\n"
            "- Are there tools like AWS CodeGuru or similar to detect secrets?\n"
            "- Are these controls consistently applied across all repositories?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
