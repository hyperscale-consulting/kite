from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_elbv2_load_balancers
from hyperscale.kite.helpers import get_account_ids_in_scope


class ElbLoggingEnabledCheck:
    def __init__(self):
        self.check_id = "elb-logging-enabled"
        self.check_name = "ELB Logging Enabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return "This check verifies that logging is enabled for all ELBs."

    def run(self) -> CheckResult:
        config = Config.get()
        elbs_without_logging = []
        elbs_with_logging = []
        accounts = get_account_ids_in_scope()
        for account in accounts:
            for region in config.active_regions:
                elbs = get_elbv2_load_balancers(account, region)
                for elb in elbs:
                    elb_name = elb.get("LoadBalancerName", "Unknown")
                    attributes = elb.get("Attributes", {})
                    access_logs_enabled = attributes.get(
                        "access_logs.s3.enabled", "false"
                    )
                    elb_info = f"ELB: {elb_name} (Account: {account}, Region: {region})"
                    if access_logs_enabled.lower() == "true":
                        elbs_with_logging.append(elb_info)
                    else:
                        elbs_without_logging.append(elb_info)
        message = "This check verifies that logging is enabled for all ELBs.\n\n"
        if elbs_without_logging:
            message += (
                "The following ELBs do not have logging enabled:\n"
                + "\n".join(f"  - {elb}" for elb in sorted(elbs_without_logging))
                + "\n\n"
            )
        if elbs_with_logging:
            message += (
                "The following ELBs have logging enabled:\n"
                + "\n".join(f"  - {elb}" for elb in sorted(elbs_with_logging))
                + "\n\n"
            )
        if not elbs_without_logging and not elbs_with_logging:
            message += "No ELBs found in any account or region.\n\n"
        if elbs_without_logging:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=message,
            )
        else:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=message,
            )
