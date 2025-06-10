"""Check for GuardDuty configuration for data at rest protection."""

from typing import Dict, Any, List, Set

from kite.data import get_guardduty_detectors
from kite.config import Config
from kite.helpers import get_account_ids_in_scope


CHECK_ID = "automate-data-at-rest-protection-with-guardduty"
CHECK_NAME = "Automate Data at Rest Protection with GuardDuty"


def _get_required_features() -> Set[str]:
    """
    Get the set of required GuardDuty features.

    Returns:
        Set[str]: Set of required feature names
    """
    return {
        "CLOUD_TRAIL",
        "DNS_LOGS",
        "FLOW_LOGS",
        "S3_DATA_EVENTS",
        "EBS_MALWARE_PROTECTION",
        "RDS_LOGIN_EVENTS",
    }


def _check_detector_features(detector: Dict[str, Any]) -> List[str]:
    """
    Check if a detector has all required features enabled.

    Args:
        detector: The GuardDuty detector to check

    Returns:
        List[str]: List of missing or disabled features
    """
    if detector["Status"] != "ENABLED":
        return ["DETECTOR_DISABLED"]

    required_features = _get_required_features()
    missing_features = []

    # Check each required feature
    for feature_name in required_features:
        feature_enabled = False
        for feature in detector.get("Features", []):
            if feature["Name"] == feature_name and feature["Status"] == "ENABLED":
                feature_enabled = True
                break
        if not feature_enabled:
            missing_features.append(feature_name)

    return missing_features


def check_automate_data_at_rest_protection_with_guardduty() -> Dict[str, Any]:
    """
    Check if GuardDuty is properly configured for data at rest protection.

    This check verifies that:
    1. GuardDuty is enabled in each account and region
    2. The following features are enabled:
       - CLOUD_TRAIL
       - DNS_LOGS
       - FLOW_LOGS
       - S3_DATA_EVENTS
       - EBS_MALWARE_PROTECTION
       - RDS_LOGIN_EVENTS

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
                - issues: Dict mapping account IDs to Dict mapping regions to lists of
                  issues
    """
    # Track issues by account and region
    issues_by_account = {}
    has_issues = False

    # Check each account
    for account_id in get_account_ids_in_scope():
        issues_by_account[account_id] = {}

        # Check each region
        for region in Config.get().active_regions:
            detectors = get_guardduty_detectors(account_id, region)

            # If no detectors found, that's an issue
            if not detectors:
                issues_by_account[account_id][region] = ["NO_DETECTORS"]
                has_issues = True
                continue

            # Check each detector
            for detector in detectors:
                missing_features = _check_detector_features(detector)
                if missing_features:
                    issues_by_account[account_id][region] = missing_features
                    has_issues = True

    # Build message
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
        for feature in sorted(_get_required_features()):
            message += f"  - {feature}\n"

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if not has_issues else "FAIL",
        "details": {
            "message": message,
            "issues": issues_by_account,
        },
    }


# Attach the check ID and name to the function
check_automate_data_at_rest_protection_with_guardduty._CHECK_ID = CHECK_ID
check_automate_data_at_rest_protection_with_guardduty._CHECK_NAME = CHECK_NAME
