from collections import defaultdict

from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_bucket_metadata
from hyperscale.kite.data import get_cloudtrail_trails
from hyperscale.kite.data import get_config_delivery_channels
from hyperscale.kite.data import get_export_tasks
from hyperscale.kite.data import get_flow_logs
from hyperscale.kite.data import get_log_groups
from hyperscale.kite.data import get_route53resolver_query_log_configs
from hyperscale.kite.helpers import get_account_ids_in_scope


def _format_log_groups_by_retention(log_groups: list[dict]) -> str:
    retention_groups = defaultdict(list)
    for group in log_groups:
        retention = group.get("retentionInDays", "Never")
        if retention == "Never":
            retention = "Never Expire"
        retention_groups[str(retention)].append(group["logGroupName"])
    output = []
    sorted_retentions = sorted(
        retention_groups.keys(),
        key=lambda x: float("inf") if x == "Never Expire" else float(x),
    )
    for retention in sorted_retentions:
        groups = retention_groups[retention]
        output.append(f"\nRetention (days): {retention}")
        for group in sorted(groups):
            output.append(f"  - {group}")
    return "\n".join(output)


def _format_export_tasks_by_retention(
    export_tasks: list[dict], buckets: list[dict]
) -> str:
    bucket_retention = {}
    for bucket in buckets:
        name = bucket.get("Name")
        if not name:
            continue
        retention = None
        lifecycle_rules = bucket.get("LifecycleRules")
        if lifecycle_rules is not None:
            for rule in lifecycle_rules:
                if "Expiration" in rule and "Days" in rule["Expiration"]:
                    days = rule["Expiration"]["Days"]
                    if retention is None or days < retention:
                        retention = days
        if retention is not None:
            bucket_retention[name] = retention
    retention_groups = defaultdict(list)
    for task in export_tasks:
        destination = task.get("destination")
        if not destination:
            continue
        bucket_name = destination.split("/")[0]
        retention = bucket_retention.get(bucket_name, "Never Expire")
        retention_groups[retention].append(f"{task['logGroupName']} -> {bucket_name}")
    output = []
    for retention, tasks in sorted(retention_groups.items()):
        output.append(f"\nS3 Retention (days): {retention}")
        for task in sorted(tasks):
            output.append(f"  - {task}")
    return "\n".join(output)


class LogRetentionCheck:
    def __init__(self):
        self.check_id = "log-retention"
        self.check_name = "Log Retention Settings"

    @property
    def question(self) -> str:
        return (
            "Are logs retained for as long as they are needed, and deleted when no "
            "longer required?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that application logs and logs for AWS services are "
            "retained for as long as required and deleted when they are no longer "
            "needed."
        )

    def run(self) -> CheckResult:
        config = Config.get()
        log_groups_by_retention = []
        export_tasks_by_retention = []
        cloudtrail_buckets_by_retention = []
        resolver_logs_by_retention = []
        flow_logs_by_retention = []
        config_buckets_by_retention = []
        accounts = get_account_ids_in_scope()
        all_buckets = {}
        for account in accounts:
            buckets = get_bucket_metadata(account)
            for bucket in buckets:
                name = bucket.get("Name")
                if name:
                    all_buckets[name] = (bucket, account)
        for account in accounts:
            for region in config.active_regions:
                log_groups = get_log_groups(account, region)
                export_tasks = get_export_tasks(account, region)
                cloudtrail_trails = get_cloudtrail_trails(account, region)
                resolver_configs = get_route53resolver_query_log_configs(
                    account, region
                )
                flow_logs = get_flow_logs(account, region)
                config_channels = get_config_delivery_channels(account, region)
                if log_groups:
                    log_groups_by_retention.append(
                        f"\nAccount: {account}, Region: {region}"
                        + _format_log_groups_by_retention(log_groups)
                    )
                if export_tasks:
                    export_tasks_by_retention.append(
                        f"\nAccount: {account}, Region: {region}"
                        + _format_export_tasks_by_retention(
                            export_tasks, [b[0] for b in all_buckets.values()]
                        )
                    )
                if cloudtrail_trails:
                    cloudtrail_buckets = []
                    for trail in cloudtrail_trails:
                        bucket_name = trail.get("S3BucketName")
                        if bucket_name and bucket_name in all_buckets:
                            bucket, bucket_account = all_buckets[bucket_name]
                            retention = None
                            lifecycle_rules = bucket.get("LifecycleRules")
                            if lifecycle_rules is not None:
                                for rule in lifecycle_rules:
                                    if (
                                        "Expiration" in rule
                                        and "Days" in rule["Expiration"]
                                    ):
                                        days = rule["Expiration"]["Days"]
                                        if retention is None or days < retention:
                                            retention = days
                            retention = (
                                retention if retention is not None else "Never Expire"
                            )
                            cloudtrail_buckets.append(
                                f"Trail: {trail.get('Name', 'Unknown')} -> "
                                f"{bucket_name} (Account: {bucket_account}, "
                                f"days) -> {retention}"
                            )
                        else:
                            if bucket_name:
                                cloudtrail_buckets.append(
                                    f"Trail: {trail.get('Name', 'Unknown')} -> "
                                    f"{bucket_name} (bucket not found in any account)"
                                )
                            else:
                                cloudtrail_buckets.append(
                                    f"Trail: {trail.get('Name', 'Unknown')} -> "
                                    f"No S3 bucket configured"
                                )
                    if cloudtrail_buckets:
                        cloudtrail_buckets_by_retention.append(
                            f"\nAccount: {account}, Region: {region}\n"
                            "CloudTrail Logging Buckets:"
                        )
                        for bucket in sorted(cloudtrail_buckets):
                            cloudtrail_buckets_by_retention.append(f"  - {bucket}")
                if resolver_configs:
                    resolver_buckets = []
                    for rc in resolver_configs:
                        destination = rc.get("DestinationArn", "")
                        if destination.startswith("arn:aws:s3:::"):
                            bucket_name = destination.split(":::")[1].split("/")[0]
                            if bucket_name in all_buckets:
                                bucket, bucket_account = all_buckets[bucket_name]
                                retention = None
                                lifecycle_rules = bucket.get("LifecycleRules")
                                if lifecycle_rules is not None:
                                    for rule in lifecycle_rules:
                                        if (
                                            "Expiration" in rule
                                            and "Days" in rule["Expiration"]
                                        ):
                                            days = rule["Expiration"]["Days"]
                                            if retention is None or days < retention:
                                                retention = days
                                retention = (
                                    retention
                                    if retention is not None
                                    else "Never Expire"
                                )
                                resolver_buckets.append(
                                    f"Config: {rc.get('Name', 'Unknown')} -> "
                                    f"{bucket_name} (Account: {bucket_account}, "
                                    f"days) -> {retention}"
                                )
                            else:
                                resolver_buckets.append(
                                    f"Config: {rc.get('Name', 'Unknown')} -> "
                                    f"{bucket_name} (bucket not found in any account)"
                                )
                    if resolver_buckets:
                        resolver_logs_by_retention.append(
                            f"\nAccount: {account}, Region: {region}\n"
                            "Route53 Resolver Query Log Configs:"
                        )
                        for bucket in sorted(resolver_buckets):
                            resolver_logs_by_retention.append(f"  - {bucket}")
                if flow_logs:
                    flow_log_buckets = []
                    for flow_log in flow_logs:
                        if flow_log.get("LogDestinationType") == "s3":
                            destination = flow_log.get("LogDestination", "")
                            if destination:
                                bucket_name = destination.split(":::")[1].split("/")[0]
                                if bucket_name in all_buckets:
                                    bucket, bucket_account = all_buckets[bucket_name]
                                    retention = None
                                    lifecycle_rules = bucket.get("LifecycleRules")
                                    if lifecycle_rules is not None:
                                        for rule in lifecycle_rules:
                                            if (
                                                "Expiration" in rule
                                                and "Days" in rule["Expiration"]
                                            ):
                                                days = rule["Expiration"]["Days"]
                                                if (
                                                    retention is None
                                                    or days < retention
                                                ):
                                                    retention = days
                                    retention = (
                                        retention
                                        if retention is not None
                                        else "Never Expire"
                                    )
                                    flow_log_buckets.append(
                                        "Flow Log: "
                                        f"{flow_log.get('FlowLogId', 'Unknown')} -> "
                                        f"{bucket_name} (Account: {bucket_account}, "
                                        f"days) -> {retention}"
                                    )
                                else:
                                    flow_log_buckets.append(
                                        f"Flow Log: "
                                        f"{flow_log.get('FlowLogId', 'Unknown')} -> "
                                        f"{bucket_name} (bucket not found in any "
                                        "account)"
                                    )
                    if flow_log_buckets:
                        flow_logs_by_retention.append(
                            f"\nAccount: {account}, Region: {region}\nVPC Flow Logs:"
                        )
                        for bucket in sorted(flow_log_buckets):
                            flow_logs_by_retention.append(f"  - {bucket}")
                if config_channels:
                    config_buckets = []
                    for channel in config_channels:
                        bucket_name = channel.get("s3BucketName")
                        if bucket_name and bucket_name in all_buckets:
                            bucket, bucket_account = all_buckets[bucket_name]
                            retention = None
                            lifecycle_rules = bucket.get("LifecycleRules")
                            if lifecycle_rules is not None:
                                for rule in lifecycle_rules:
                                    if (
                                        "Expiration" in rule
                                        and "Days" in rule["Expiration"]
                                    ):
                                        days = rule["Expiration"]["Days"]
                                        if retention is None or days < retention:
                                            retention = days
                            retention = (
                                retention if retention is not None else "Never Expire"
                            )
                            config_buckets.append(
                                f"Channel: {channel.get('name', 'Unknown')} -> "
                                f"{bucket_name} (Account: {bucket_account}, "
                                f"days) -> {retention}"
                            )
                        else:
                            if bucket_name:
                                config_buckets.append(
                                    f"Channel: {channel.get('name', 'Unknown')} -> "
                                    f"{bucket_name} (bucket not found in any account)"
                                )
                            else:
                                config_buckets.append(
                                    f"Channel: {channel.get('name', 'Unknown')} -> "
                                    f"No S3 bucket configured"
                                )
                    if config_buckets:
                        config_buckets_by_retention.append(
                            f"\nAccount: {account}, Region: {region}\n"
                            "AWS Config Delivery Channel Buckets:"
                        )
                        for bucket in sorted(config_buckets):
                            config_buckets_by_retention.append(f"  - {bucket}")
        message = (
            "Current CloudWatch Log Groups:\n"
            + "\n".join(log_groups_by_retention)
            + "\n\nCurrent Log Export Tasks:\n"
            + "\n".join(export_tasks_by_retention)
            + "\n\nCloudTrail Logging Buckets:\n"
            + "\n".join(cloudtrail_buckets_by_retention)
            + "\n\nRoute53 Resolver Query Log Configs:\n"
            + "\n".join(resolver_logs_by_retention)
            + "\n\nVPC Flow Logs:\n"
            + "\n".join(flow_logs_by_retention)
            + "\n\nAWS Config Delivery Channel Buckets:\n"
            + "\n".join(config_buckets_by_retention)
            + "\n\nPlease review the retention periods above and consider:\n"
            "- Are logs retained for as long as required by security requirements?\n"
            "- Are logs retained for longer than necessary?"
        )
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
        )
