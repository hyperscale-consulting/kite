from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class DataCatalogCheck:
    def __init__(self):
        self.check_id = "data-catalog"
        self.check_name = "Data Catalog"

    @property
    def question(self) -> str:
        return (
            "Is there an inventory of all data within the organization, including "
            "its location, sensitivity level, owner, and the controls in place to "
            "protect that data?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is an inventory of all data within the "
            "organization that includes location, sensitivity, ownership, retention, "
            "and controls in place to protect the data."
        )

    def run(self) -> CheckResult:
        message = (
            "Please confirm whether there is an inventory of all data within the "
            "organization that includes:\n\n"
            "- Location\n"
            "- Sensitivity level\n"
            "- Ownership\n"
            "- Retention period\n"
            "- Controls in place to protect the data\n\n"
            "Consider the following factors:\n"
            "- Is the data catalog comprehensive and up-to-date?\n"
            "- Are data owners clearly identified and accountable?\n"
            "- Are sensitivity levels consistently applied?\n"
            "- Are security controls documented and validated?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
