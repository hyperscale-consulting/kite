from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class SecurityEventCorrelationCheck:
    def __init__(self):
        self.check_id = "security-event-correlation"
        self.check_name = "Security Event Correlation and Enrichment"

    @property
    def question(self) -> str:
        return (
            "Are there automated mechanisms for correlating and enriching security "
            "events across these data sources?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there are automated mechanisms for correlating "
            "and enriching security events across different data sources."
        )

    def run(self) -> CheckResult:
        context = (
            "Are there automated mechanisms for correlating and "
            "enriching security events across different data sources.\n\n"
            "Examples of data sources that can be used for correlation and "
            "enrichment:\n"
            "- CloudTrail logs\n"
            "- VPC flow logs\n"
            "- Route 53 resolver logs\n"
            "- Infrastructure logs\n"
            "- Application logs\n\n"
            "The correlation and enrichment process should:\n"
            "- Combine related events across different sources\n"
            "- Add context to security events - for example via notes and user defined "
            "fields in AWS Security Hub\n"
            "- Help identify patterns and anomalies\n"
            "- Support incident investigation and response"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
