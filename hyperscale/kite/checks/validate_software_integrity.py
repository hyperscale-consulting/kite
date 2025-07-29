from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class ValidateSoftwareIntegrityCheck:
    def __init__(self):
        self.check_id = "validate-software-integrity"
        self.check_name = "Validate Software Integrity"

    @property
    def question(self) -> str:
        return (
            "Is the integrity of software validated using cryptographic signatures "
            "where available, and are published artifacts cryptographically signed?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that the integrity of software is validated using "
            "cryptographic signatures where available, and that published artifacts "
            "are cryptographically signed."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Are software packages validated using cryptographic signatures "
            "before installation?\n"
            "- Are container images signed and verified before deployment?\n"
            "- Are application artifacts signed?\n"
            "- Are third-party dependencies validated for integrity?\n"
            "- Are signing keys properly managed and rotated?\n"
            "- Is signature verification automated in CI/CD pipelines?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
