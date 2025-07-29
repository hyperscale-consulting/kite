from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class TrainForApplicationSecurityCheck:
    def __init__(self):
        self.check_id = "train-for-application-security"
        self.check_name = "Train for Application Security"

    @property
    def question(self) -> str:
        return (
            "Do engineers receive training on application security topics including "
            "threat modeling, secure coding, security testing, and secure deployment "
            "practices?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that engineers receive training on application "
            "security topics including threat modeling, secure coding, security "
            "testing, and secure deployment practices."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Do engineers receive training on threat modeling and risk assessment?\n"
            "- Is there training on secure coding practices and common "
            "vulnerabilities?\n"
            "- Are engineers trained on security testing techniques and tools?\n"
            "- Is there training on secure deployment practices and configuration?\n"
            "- Is the training regularly updated to cover new threats and best "
            "practices?\n"
            "- Are there mechanisms to verify the effectiveness of the training?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
