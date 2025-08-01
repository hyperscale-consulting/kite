from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.helpers import is_identity_center_enabled


class ScimProtocolUsedCheck:
    def __init__(self):
        self.check_id = "scim-protocol-used"
        self.check_name = "SCIM Protocol Used for IAM Identity Center"

    @property
    def question(self) -> str:
        return (
            "Is the System for Cross-domain Identity Management (SCIM) protocol used "
            "to synchronize user and group information from the external identity "
            "provider into IAM Identity Center's data store?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that the System for Cross-domain Identity Management "
            "(SCIM) protocol is used to synchronize user and group information from "
            "the external identity provider into IAM Identity Center's data store."
        )

    def run(self) -> CheckResult:
        identity_center_enabled = is_identity_center_enabled()

        if not identity_center_enabled:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="Identity Center is not enabled.",
            )

        context_message = (
            "Consider the following factors:\n"
            "- Is the SCIM protocol configured for user synchronization?\n"
            "- Is the SCIM protocol configured for group synchronization?\n"
            "- Are changes in the external identity provider automatically reflected "
            "in IAM Identity Center?\n"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=context_message,
        )
