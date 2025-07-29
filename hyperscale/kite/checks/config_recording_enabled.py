from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_config_recorders
from hyperscale.kite.helpers import get_account_ids_in_scope


class ConfigRecordingEnabledCheck:
    def __init__(self):
        self.check_id = "config-recording-enabled"
        self.check_name = "AWS Config Recording Enabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that AWS Config recorders are enabled in all active "
            "regions "
            "for all in-scope accounts."
        )

    def run(self) -> CheckResult:
        config = Config.get()
        missing_recorders = []
        recorders_found = []
        accounts = get_account_ids_in_scope()
        for account in accounts:
            for region in config.active_regions:
                recorders = get_config_recorders(account, region)
                if recorders:
                    recorders_found.extend(recorders)
                else:
                    missing_recorders.append(dict(account=account, region=region))
        passed = not missing_recorders
        return CheckResult(
            status=CheckStatus.PASS if passed else CheckStatus.FAIL,
            reason=(
                "AWS Config recording is enabled in all active regions for all "
                "in-scope accounts."
                if passed
                else f"Missing AWS Config recorders in {len(missing_recorders)} "
                "account/region(s)."
            ),
            details={
                "missing_recorders": missing_recorders,
                "recorders_found": recorders_found,
            },
        )
