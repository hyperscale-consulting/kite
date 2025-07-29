from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class DetectSensitiveDataTransformCheck:
    def __init__(self):
        self.check_id = "detect-sensitive-data-transform"
        self.check_name = "Detect Sensitive Data Transform"

    @property
    def question(self) -> str:
        return (
            "Is the detect sensitive data transform used in any Glue ETL jobs to "
            "detect and handle sensitive data?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that the Detect Sensitive Data transform is used "
            "in Glue ETL jobs to detect and handle sensitive data."
        )

    def run(self) -> CheckResult:
        message = (
            "The Detect PII transform provides the ability to detect, mask, or remove "
            "entities that you define, or are pre-defined by AWS. This enables you to "
            "increase compliance and reduce liability."
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
