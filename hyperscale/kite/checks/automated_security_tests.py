from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class AutomatedSecurityTestsCheck:
    def __init__(self):
        self.check_id = "automated-security-tests"
        self.check_name = "Automated Security Tests"

    @property
    def question(self) -> str:
        return (
            "Are automated unit and integration tests used to verify the security "
            "properties of applications?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that security tests are automated throughout the "
            "development and release lifecycle."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are there automated tests for security-critical functionality?\n"
            "- Are there tests for authentication and authorization mechanisms?\n"
            "- Are there tests for input validation and sanitization?\n"
            "- Are there tests for secure configuration settings?\n"
            "- Are these tests integrated into the CI/CD pipeline?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
