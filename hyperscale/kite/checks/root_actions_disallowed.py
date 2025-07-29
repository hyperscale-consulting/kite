from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.scps import check_for_org_wide_disallow_root_actions_scp
from hyperscale.kite.data import get_organization


class RootActionsDisallowedCheck:
    def __init__(self):
        self.check_id = "root-actions-disallowed"
        self.check_name = "Root Actions Disallowed"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that SCPs are applied that prevent root user "
            "actions across the whole organization."
        )

    def run(self) -> CheckResult:
        return check_for_org_wide_disallow_root_actions_scp(get_organization())
