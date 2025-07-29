from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class UseHardenedImagesCheck:
    def __init__(self):
        self.check_id = "use-hardened-images"
        self.check_name = "Use Hardened Images"

    @property
    def question(self) -> str:
        return (
            "Is compute provisioned from hardened images, applying controls such as "
            "those from CIS and DISA STIGs?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that compute is provisioned from hardened images, "
            "applying controls such as those from the Center for Internet Security "
            "(CIS) and the Defense Information Systems Agency (DISA) Security "
            "Technical Implementation Guides (STIGs)."
        )

    def run(self) -> CheckResult:
        context = (
            "Consider the following factors:\n"
            "- Are compute instances provisioned from hardened images?\n"
            "- Do the hardened images apply security controls from CIS benchmarks?\n"
            "- Do the hardened images apply security controls from DISA STIGs?\n"
            "- Are the hardened images regularly updated and maintained?\n"
            "- Are the hardened images validated and tested before deployment?\n"
            "- Is there a process for creating and maintaining hardened images?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
