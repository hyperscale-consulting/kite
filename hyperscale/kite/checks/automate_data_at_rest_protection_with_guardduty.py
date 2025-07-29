from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_guardduty_detectors
from hyperscale.kite.helpers import get_account_ids_in_scope


class AutomateDataAtRestProtectionWithGuardDutyCheck:
    def __init__(self):
        self.check_id = "automate-data-at-rest-protection-with-guardduty"
        self.check_name = "Automate Data at Rest Protection with GuardDuty"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that GuardDuty is enabled in each account and region "
            "and that the following features are enabled: CLOUD_TRAIL, DNS_LOGS, "
            "FLOW_LOGS, S3_DATA_EVENTS, EBS_MALWARE_PROTECTION, RDS_LOGIN_EVENTS."
        )

    def _get_required_features(self) -> set[str]:
        return {
            "CLOUD_TRAIL",
            "DNS_LOGS",
            "FLOW_LOGS",
            "S3_DATA_EVENTS",
            "EBS_MALWARE_PROTECTION",
            "RDS_LOGIN_EVENTS",
        }

    def _check_detector_features(self, detector) -> list[str]:
        if detector["Status"] != "ENABLED":
            return ["DETECTOR_DISABLED"]
        required_features = self._get_required_features()
        missing_features = []
        for feature_name in required_features:
            feature_enabled = False
            for feature in detector.get("Features", []):
                if feature["Name"] == feature_name and feature["Status"] == "ENABLED":
                    feature_enabled = True
                    break
            if not feature_enabled:
                missing_features.append(feature_name)
        return missing_features

    def run(self) -> CheckResult:
        issues_by_account = {}
        has_issues = False
        for account_id in get_account_ids_in_scope():
            issues_by_account[account_id] = {}
            for region in Config.get().active_regions:
                detectors = get_guardduty_detectors(account_id, region)
                if not detectors:
                    issues_by_account[account_id][region] = ["NO_DETECTORS"]
                    has_issues = True
                    continue
                for detector in detectors:
                    missing_features = self._check_detector_features(detector)
                    if missing_features:
                        issues_by_account[account_id][region] = missing_features
                        has_issues = True
        message = "GuardDuty Configuration for Data at Rest Protection:\n\n"
        if has_issues:
            message += "The following issues were found:\n\n"
            for account_id, regions in issues_by_account.items():
                if regions:
                    message += f"Account: {account_id}\n"
                    for region, issues in regions.items():
                        message += f"  Region: {region}\n"
                        for issue in issues:
                            if issue == "NO_DETECTORS":
                                message += "    - No GuardDuty detectors found\n"
                            elif issue == "DETECTOR_DISABLED":
                                message += "    - GuardDuty detector is disabled\n"
                            else:
                                message += f"    - Feature {issue} is not enabled\n"
                        message += "\n"
        else:
            message += "GuardDuty is properly configured for data at rest protection:\n"
            message += "- GuardDuty is enabled in all accounts and regions\n"
            message += "- All required features are enabled:\n"
            for feature in sorted(self._get_required_features()):
                message += f"  - {feature}\n"
        return CheckResult(
            status=CheckStatus.PASS if not has_issues else CheckStatus.FAIL,
            reason=message,
            details={
                "issues": issues_by_account,
            },
        )
