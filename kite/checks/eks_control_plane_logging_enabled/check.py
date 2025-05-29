"""Check for EKS control plane logging configuration."""

from typing import Dict, Any, List

from kite.data import (
    get_eks_clusters,
)
from kite.helpers import get_account_ids_in_scope
from kite.config import Config


CHECK_ID = "eks-control-plane-logging-enabled"
CHECK_NAME = "EKS Control Plane Logging Enabled"


def check_eks_control_plane_logging_enabled() -> Dict[str, Any]:
    """
    Check if logging is enabled for all EKS clusters with all required log types.

    This check:
    1. Gets all EKS clusters in each account and region
    2. Verifies that each cluster has logging enabled
    3. Verifies that each cluster has all required log types enabled:
       - api
       - audit
       - authenticator
       - controllerManager
       - scheduler
    4. Fails if any clusters are found without logging enabled or missing required log types

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    config = Config.get()
    clusters_without_logging = []
    clusters_with_incomplete_logging = []
    clusters_with_logging = []

    # Required log types
    required_log_types = {
        "api",
        "audit",
        "authenticator",
        "controllerManager",
        "scheduler",
    }

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # Check each account in each active region
    for account in accounts:
        for region in config.active_regions:
            # Get EKS clusters for this account and region
            clusters = get_eks_clusters(account, region)

            # Check each cluster
            for cluster in clusters:
                cluster_name = cluster.get("name", "Unknown")
                logging_config = cluster.get("logging", {})
                cluster_logging = logging_config.get("clusterLogging", [])
                enabled = False
                enabled_types = set()

                # Check if logging is enabled and get enabled log types
                for log_config in cluster_logging:
                    if log_config.get("enabled", False):
                        enabled = True
                        enabled_types.update(log_config.get("types", []))

                cluster_info = (
                    f"Cluster: {cluster_name} "
                    f"(Account: {account}, Region: {region})"
                )

                if not enabled:
                    clusters_without_logging.append(cluster_info)
                elif not required_log_types.issubset(enabled_types):
                    missing_types = required_log_types - enabled_types
                    clusters_with_incomplete_logging.append(
                        f"{cluster_info} - Missing log types: {', '.join(sorted(missing_types))}"
                    )
                else:
                    clusters_with_logging.append(cluster_info)

    # Build the message
    message = (
        "This check verifies that logging is enabled for all EKS clusters "
        "with all required log types (api, audit, authenticator, "
        "controllerManager, scheduler).\n\n"
    )

    if clusters_without_logging:
        message += (
            "The following clusters do not have logging enabled:\n"
            + "\n".join(f"  - {cluster}" for cluster in sorted(clusters_without_logging))
            + "\n\n"
        )

    if clusters_with_incomplete_logging:
        message += (
            "The following clusters have logging enabled but are missing "
            "required log types:\n"
            + "\n".join(f"  - {cluster}" for cluster in sorted(clusters_with_incomplete_logging))
            + "\n\n"
        )

    if clusters_with_logging:
        message += (
            "The following clusters have logging enabled with all required "
            "log types:\n"
            + "\n".join(f"  - {cluster}" for cluster in sorted(clusters_with_logging))
            + "\n\n"
        )

    if not clusters_without_logging and not clusters_with_incomplete_logging and not clusters_with_logging:
        message += "No EKS clusters found in any account or region.\n\n"

    # Determine status based on whether any clusters are missing logging or required log types
    if clusters_without_logging or clusters_with_incomplete_logging:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "FAIL",
            "details": {
                "message": message,
            },
        }
    else:
        return {
            "check_id": CHECK_ID,
            "check_name": CHECK_NAME,
            "status": "PASS",
            "details": {
                "message": message,
            },
        }


# Attach the check ID and name to the function
check_eks_control_plane_logging_enabled._CHECK_ID = CHECK_ID
check_eks_control_plane_logging_enabled._CHECK_NAME = CHECK_NAME
