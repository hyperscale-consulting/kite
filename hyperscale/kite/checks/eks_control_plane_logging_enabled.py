from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_eks_clusters
from hyperscale.kite.helpers import get_account_ids_in_scope


class EksControlPlaneLoggingEnabledCheck:
    def __init__(self):
        self.check_id = "eks-control-plane-logging-enabled"
        self.check_name = "EKS Control Plane Logging Enabled"

    @property
    def question(self) -> str:
        return ""  # fully automated check

    @property
    def description(self) -> str:
        return (
            "This check verifies that logging is enabled for all EKS clusters "
            "with all required log types (api, audit, authenticator, "
            "controllerManager, scheduler)."
        )

    def run(self) -> CheckResult:
        config = Config.get()
        without_logging = []
        with_incomplete_logging = []
        with_logging = []

        required_log_types = {
            "api",
            "audit",
            "authenticator",
            "controllerManager",
            "scheduler",
        }

        accounts = get_account_ids_in_scope()

        for account in accounts:
            for region in config.active_regions:
                clusters = get_eks_clusters(account, region)
                for cluster in clusters:
                    cluster_name = cluster.get("name", "Unknown")
                    logging_config = cluster.get("logging", {})
                    cluster_logging = logging_config.get("clusterLogging", [])
                    enabled = False
                    enabled_types = set()
                    for log_config in cluster_logging:
                        if log_config.get("enabled", False):
                            enabled = True
                            enabled_types.update(log_config.get("types", []))
                    cluster_info = (
                        f"Cluster: {cluster_name} (Account: {account}, "
                        f"Region: {region})"
                    )
                    if not enabled:
                        without_logging.append(cluster_info)
                    elif not required_log_types.issubset(enabled_types):
                        missing_types = required_log_types - enabled_types
                        with_incomplete_logging.append(
                            f"{cluster_info} - Missing log types: "
                            f"{', '.join(sorted(missing_types))}"
                        )
                    else:
                        with_logging.append(cluster_info)

        message = ""

        if without_logging:
            message += (
                "The following clusters do not have logging enabled:\n"
                + "\n".join(f"  - {cluster}" for cluster in sorted(without_logging))
                + "\n\n"
            )
        if with_incomplete_logging:
            message += (
                "The following clusters have logging enabled but are missing "
                "required log types:\n"
                + "\n".join(
                    f"  - {cluster}" for cluster in sorted(with_incomplete_logging)
                )
                + "\n\n"
            )
        if with_logging:
            message += (
                "The following clusters have logging enabled with all required "
                "log types:\n"
                + "\n".join(f"  - {cluster}" for cluster in sorted(with_logging))
                + "\n\n"
            )
        if not without_logging and not with_incomplete_logging and not with_logging:
            message += "No EKS clusters found in any account or region.\n\n"

        if without_logging or with_incomplete_logging:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason="Some EKS clusters are missing logging or required log types.",
                details={
                    "without_logging": without_logging,
                    "with_incomplete_logging": with_incomplete_logging,
                    "with_logging": with_logging,
                },
            )
        else:
            return CheckResult(
                status=CheckStatus.PASS,
                reason=(
                    "All EKS clusters have logging enabled with all required log types."
                ),
                details={
                    "with_logging": with_logging,
                },
            )
