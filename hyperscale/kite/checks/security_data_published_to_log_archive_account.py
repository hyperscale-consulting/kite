from collections import defaultdict

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_cloudtrail_trails
from hyperscale.kite.data import get_config_delivery_channels
from hyperscale.kite.data import get_export_tasks
from hyperscale.kite.data import get_flow_logs
from hyperscale.kite.data import get_organization
from hyperscale.kite.data import get_route53resolver_query_log_configs
from hyperscale.kite.helpers import get_account_ids_in_scope


class SecurityDataPublishedToLogArchiveAccountCheck:
    def __init__(self):
        self.check_id = "security-data-published-to-log-archive-account"
        self.check_name = "Security Data Published to Log Archive Account"

    @property
    def question(self) -> str:
        return "Is security data published to a centralized log archive account?"

    @property
    def description(self) -> str:
        return (
            "This check verifies if security data is published to a centralized "
            "log archive account."
        )

    def _extract_bucket_name(self, destination: str) -> str:
        """
        Extract bucket name from various destination formats.

        Args:
            destination: Destination string (ARN, bucket name, etc.)

        Returns:
            Bucket name or empty string if not found
        """
        if not destination:
            return ""

        # Handle S3 ARNs
        if destination.startswith("arn:aws:s3:::"):
            return destination.split(":::")[1].split("/")[0]

        if destination.startswith("arn:aws:logs"):
            return ""

        # Handle simple bucket names
        if "/" not in destination:
            return destination

        # Handle paths
        return destination.split("/")[0]

    def run(self) -> CheckResult:
        """
        Check if security data is published to a centralized log archive account.

        This check:
        1. Verifies if an organization exists
        2. Looks for a Log Archive account
        3. Checks various security data sources for their logging destinations
        4. Reports which items are logging to the archive account vs elsewhere
        """
        config = Config.get()

        # Check if organization exists
        org = get_organization()
        if not org:
            return CheckResult(
                status=CheckStatus.FAIL,
                reason=(
                    "No AWS Organization found. This check requires an organization."
                ),
            )

        # Find Log Archive account
        log_archive_account = None
        for account in org.get_accounts():
            if account.name == "Log Archive":
                log_archive_account = account
                break

        destination_buckets = defaultdict(list)
        other_destinations = []

        # Check each account in each active region
        for account in get_account_ids_in_scope():
            for region in config.active_regions:
                # Get export tasks
                export_tasks = get_export_tasks(account, region)
                for task in export_tasks:
                    bucket = self._extract_bucket_name(task.get("destination", ""))
                    if bucket:
                        destination_buckets[bucket].append(
                            f"Log export task in account {account} - {region}"
                        )
                    else:
                        other_destinations.append(
                            f"Log export task in account {account} - {region}"
                        )

                # Get CloudTrail trails
                trails = get_cloudtrail_trails(account, region)
                for trail in trails:
                    bucket = trail.get("S3BucketName", "")
                    if bucket:
                        destination_buckets[bucket].append(
                            f"CloudTrail {trail['Name']} in account {account} - "
                            f"{region}"
                        )
                    else:
                        other_destinations.append(
                            f"CloudTrail {trail['Name']} in account {account} - "
                            f"{region}"
                        )

                # Get Route53 Resolver query log configs
                resolver_configs = get_route53resolver_query_log_configs(
                    account, region
                )
                for resolver_config in resolver_configs:
                    destination = resolver_config.get("DestinationArn", "")
                    bucket = self._extract_bucket_name(destination)
                    if bucket:
                        destination_buckets[bucket].append(
                            f"Route53 resolver query log in account {account} - "
                            f"{region}"
                        )
                    else:
                        other_destinations.append(
                            f"Route53 resolver query log in account {account} - "
                            f"{region}"
                        )

                # Get VPC flow logs
                flow_logs = get_flow_logs(account, region)
                for flow_log in flow_logs:
                    if flow_log.get("LogDestinationType") == "s3":
                        destination = flow_log.get("LogDestination", "")
                        bucket = self._extract_bucket_name(destination)
                        if bucket:
                            destination_buckets[bucket].append(
                                f"VPC flow log in account {account} - {region}"
                            )
                        else:
                            other_destinations.append(
                                f"VPC flow log in account {account} - {region}"
                            )
                    else:
                        other_destinations.append(
                            f"VPC flow log in account {account} - {region}"
                        )

                # Get AWS Config delivery channels
                config_channels = get_config_delivery_channels(account, region)
                for channel in config_channels:
                    bucket = channel.get("s3BucketName", "")
                    if bucket:
                        destination_buckets[bucket].append(
                            f"Config recorder in account {account} - {region}"
                        )
                    else:
                        other_destinations.append(
                            f"Config recorder in account {account} - {region}"
                        )

        # Build the message
        message = ""

        if log_archive_account:
            message += (
                f"Log Archive account found:\n"
                f"  Account ID: {log_archive_account.id}\n"
                f"  Account Name: {log_archive_account.name}\n\n"
            )
        else:
            message += "No Log Archive account found.\n\n"

        message += "Current Security Data Destinations:\n"
        for bucket, source in destination_buckets.items():
            message += f"\t{bucket} <- \n\t\t" + "\n\t\t".join(source) + "\n"

        message += "\nOther Security Data Destinations:\n"
        for destination in other_destinations:
            message += f"\t{destination}\n"

        message += (
            "\n\nPlease review the destinations above and consider:\n"
            "- Is security data being centralized in the Log Archive account?\n"
            "- Are there any security data sources logging to other locations?"
        )

        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
