from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class EmployUserGroupsAndAttributesCheck:
    def __init__(self):
        self.check_id = "employ-user-groups-and-attributes"
        self.check_name = "Employ User Groups and Attributes"

    @property
    def question(self) -> str:
        return "Are permissions defined according to user groups and attributes?"

    @property
    def description(self) -> str:
        return (
            "Check to verify if permissions are defined according to user groups and "
            "attributes."
        )

    def run(self) -> CheckResult:
        message = (
            "IAM data has been saved to .kite/audit/<account_id>/ for review.\n\n"
            "Please review the files for each account:\n"
            "\nConsider the following questions:\n"
            "1. Are permissions defined and duplicated individually for users?\n"
            "2. Are groups defined at too high a level, granting overly broad "
            "permissions?\n"
            "3. Are groups too granular, creating duplication and confusion?\n"
            "4. Do groups have duplicate permissions where attributes could be used "
            "instead?\n"
            "5. Are groups based on function, rather than resource access?\n\n"
            "Tip: focus on users, groups, and roles that can be assumed by humans, "
            "and look for condition clauses that constrain access based on tags.\n"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
