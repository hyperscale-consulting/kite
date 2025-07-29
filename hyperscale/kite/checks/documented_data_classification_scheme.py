from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus


class DocumentedDataClassificationSchemeCheck:
    def __init__(self):
        self.check_id = "documented-data-classification-scheme"
        self.check_name = "Documented Data Classification Scheme"

    @property
    def question(self) -> str:
        return (
            "Is there a documented data classification scheme that describes "
            "handling requirements, lifecycle, backup, encryption policies, access "
            "control, destruction and auditing of access?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is a documented data classification "
            "scheme that describes the data classification levels and, for each level "
            "and for each state (at rest, in transit and in use), the controls that "
            "should be in place."
        )

    def run(self) -> CheckResult:
        message = (
            "Confirm whether there is a documented data classification scheme that "
            "describes the data classification levels and, for each level each state "
            "(at rest, in transit and in use), the controls that should be in place "
            "including:\n\n"
            "- Data handling requirements\n"
            "- Data lifecycle management\n"
            "- Backup requirements\n"
            "- Encryption policies\n"
            "- Access control requirements\n"
            "- Data destruction procedures\n"
            "- Access auditing requirements\n\n"
            "Consider the following factors:\n"
            "- Is the classification scheme comprehensive and covers all data types?\n"
            "- Are the requirements clear and actionable?\n"
            "- Is the scheme regularly reviewed and updated?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
