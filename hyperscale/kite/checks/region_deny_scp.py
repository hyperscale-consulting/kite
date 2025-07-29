from hyperscale.kite.checks import CheckResult
from hyperscale.kite.checks import CheckStatus
from hyperscale.kite.checks.scps import check_for_org_wide_region_deny_scp
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_organization


class RegionDenyScpCheck:
    def __init__(self):
        self.check_id = "region-deny-scp"
        self.check_name = "Region Deny SCP"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that there is an SCP that denies access to all "
            "regions except those configured as active regions, and that the SCP is "
            "attached to either the root OU or all top-level OUs."
        )

    def run(self) -> CheckResult:
        config = Config.get()
        if not config.active_regions:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="No active regions configured.",
            )
        return check_for_org_wide_region_deny_scp(
            get_organization(), config.active_regions
        )
