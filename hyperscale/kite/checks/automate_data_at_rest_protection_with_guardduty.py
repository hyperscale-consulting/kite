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
        if has_issues:
            reason = "GuardDuty detectors were missing, disabled, or missing features."
        else:
            reason = "GuardDuty is properly configured for data at rest protection"
        return CheckResult(
            status=CheckStatus.PASS if not has_issues else CheckStatus.FAIL,
            reason=reason,
            details={
                "issues": issues_by_account,
            },
        )

    @property
    def criticality(self) -> int:
        return 6

    @property
    def difficulty(self) -> int:
        return 5
