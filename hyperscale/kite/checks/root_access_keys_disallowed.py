from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.scps import (
    check_for_org_wide_disallow_root_create_access_key_scp,
)
from hyperscale.kite.data import get_organization


class RootAccessKeysDisallowedCheck:
    def __init__(self):
        self.check_id = "root-access-keys-disallowed"
        self.check_name = "Root Access Keys Disallowed"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that SCPs are applied that prevent the "
            "iam:CreateAccessKey action for the root user across the whole "
            "organization."
        )

    def run(self) -> CheckResult:
        return check_for_org_wide_disallow_root_create_access_key_scp(
            get_organization()
        )
