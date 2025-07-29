from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class RestoreTestingCheck:
    def __init__(self):
        self.check_id = "restore-testing"
        self.check_name = "Restore Testing"

    @property
    def question(self) -> str:
        return (
            "Are backups regularly tested automatically for restore viability and "
            "restore job duration?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that backups are regularly tested for restore "
            "viability and duration. Backups should be tested automatically to ensure "
            "they can be restored successfully and within acceptable timeframes."
        )

    def run(self) -> CheckResult:
        context = (
            "Please review your backup restore testing procedures and confirm:\n\n"
            "1. Backups are regularly tested automatically for restore viability\n"
            "2. Restore job duration is monitored and documented\n"
            "3. Restore testing results are reviewed and any issues are addressed\n"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context,
        )
