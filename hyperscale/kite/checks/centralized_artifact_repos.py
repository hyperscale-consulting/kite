from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class CentralizedArtifactReposCheck:
    def __init__(self):
        self.check_id = "use-centralized-artifact-repos"
        self.check_name = "Use Centralized Artifact Repositories"

    @property
    def question(self) -> str:
        return (
            "Are centralized artifact repositories used to mitigate threats such as "
            "dependency confusion attacks?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that centralized artifact repositories are used to "
            "mitigate threats such as dependency confusion and typosquatting attacks."
        )

    def run(self) -> CheckResult:
        message = (
            "Consider the following factors:\n"
            "- Are artifact repositories (e.g., npm, PyPI, Maven) hosted internally?\n"
            "- Are packages validated before use?\n"
            "- Is the use of vulnerable / malicious packages detected and remediated, "
            "or prevented?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
