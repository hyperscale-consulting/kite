"""Check for log retention settings."""

from typing import Dict, Any, List
from collections import defaultdict

from kite.data import (
    get_log_groups,
    get_export_tasks,
    get_bucket_metadata,
    get_cloudtrail_trails,
    get_route53resolver_query_log_configs,
    get_flow_logs,
)
from kite.helpers import get_account_ids_in_scope, manual_check
from kite.config import Config


CHECK_ID = "log-retention"
CHECK_NAME = "Log Retention Settings"


def _format_log_groups_by_retention(log_groups: List[Dict[str, Any]]) -> str:
    """
    Format log groups grouped by their retention period.

    Args:
        log_groups: List of log group dictionaries

    Returns:
        Formatted string showing log groups grouped by retention period
    """
    # Group log groups by retention period
    retention_groups = defaultdict(list)
    for group in log_groups:
        retention = group.get("retentionInDays", "Never")
        if retention == "Never":
            retention = "Never Expire"
        # Convert retention to string for consistent sorting
        retention_groups[str(retention)].append(group["logGroupName"])

    # Format the output
    output = []
    # Sort by retention period, handling "Never Expire" specially
    sorted_retentions = sorted(
        retention_groups.keys(),
        key=lambda x: float('inf') if x == "Never Expire" else float(x)
    )
    for retention in sorted_retentions:
        groups = retention_groups[retention]
        output.append(f"\nRetention (days): {retention}")
        for group in sorted(groups):
            output.append(f"  - {group}")

    return "\n".join(output)


def _format_export_tasks_by_retention(
    export_tasks: List[Dict[str, Any]], buckets: List[Dict[str, Any]]
) -> str:
    """
    Format export tasks grouped by their S3 bucket retention period.

    Args:
        export_tasks: List of export task dictionaries
        buckets: List of S3 bucket dictionaries

    Returns:
        Formatted string showing export tasks grouped by retention period
    """
    # Create a map of bucket names to their retention periods
    bucket_retention = {}
    for bucket in buckets:
        name = bucket.get("Name")
        if not name:
            continue

        # Find the shortest expiration period in lifecycle rules
        retention = None
        lifecycle_rules = bucket.get("LifecycleRules")
        if lifecycle_rules is not None:  # Check if LifecycleRules exists
            for rule in lifecycle_rules:
                if "Expiration" in rule and "Days" in rule["Expiration"]:
                    days = rule["Expiration"]["Days"]
                    if retention is None or days < retention:
                        retention = days

        if retention is not None:
            bucket_retention[name] = retention

    # Group export tasks by bucket retention period
    retention_groups = defaultdict(list)
    for task in export_tasks:
        destination = task.get("destination")
        if not destination:
            continue

        # Extract bucket name from destination
        bucket_name = destination.split("/")[0]
        retention = bucket_retention.get(bucket_name, "Never Expire")
        retention_groups[retention].append(
            f"{task['logGroupName']} -> {bucket_name}"
        )

    # Format the output
    output = []
    for retention, tasks in sorted(retention_groups.items()):
        output.append(f"\nS3 Retention (days): {retention}")
        for task in sorted(tasks):
            output.append(f"  - {task}")

    return "\n".join(output)


def check_log_retention() -> Dict[str, Any]:
    """
    Check if logs are retained for a suitable period.

    This check:
    1. Shows CloudWatch log groups grouped by their retention period
    2. Shows log export tasks grouped by their S3 bucket retention period
    3. Shows CloudTrail logging buckets and their retention periods
    4. Shows Route53 Resolver query log configs and their S3 bucket retention periods
    5. Shows VPC flow logs and their S3 bucket retention periods
    6. Asks the user to confirm if logs are retained for as long as required

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS" or "FAIL")
            - details: Dict containing:
                - message: str describing the result
    """
    config = Config.get()
    log_groups_by_retention = []
    export_tasks_by_retention = []
    cloudtrail_buckets_by_retention = []
    resolver_logs_by_retention = []
    flow_logs_by_retention = []

    # Get all in-scope accounts
    accounts = get_account_ids_in_scope()

    # First, build a map of all buckets across all accounts
    all_buckets = {}
    for account in accounts:
        buckets = get_bucket_metadata(account)
        for bucket in buckets:
            name = bucket.get("Name")
            if name:
                all_buckets[name] = (bucket, account)

    # Check each account in each active region
    for account in accounts:
        for region in config.active_regions:
            # Get log groups and export tasks for this account and region
            log_groups = get_log_groups(account, region)
            export_tasks = get_export_tasks(account, region)
            cloudtrail_trails = get_cloudtrail_trails(account, region)
            resolver_configs = get_route53resolver_query_log_configs(account, region)
            flow_logs = get_flow_logs(account, region)

            if log_groups:
                log_groups_by_retention.append(
                    f"\nAccount: {account}, Region: {region}"
                    + _format_log_groups_by_retention(log_groups)
                )

            if export_tasks:
                export_tasks_by_retention.append(
                    f"\nAccount: {account}, Region: {region}"
                    + _format_export_tasks_by_retention(export_tasks, [b[0] for b in all_buckets.values()])
                )

            # Process CloudTrail trails
            if cloudtrail_trails:
                cloudtrail_buckets = []
                for trail in cloudtrail_trails:
                    bucket_name = trail.get("S3BucketName")
                    if bucket_name and bucket_name in all_buckets:
                        bucket, bucket_account = all_buckets[bucket_name]
                        # Find the shortest expiration period in lifecycle rules
                        retention = None
                        lifecycle_rules = bucket.get("LifecycleRules")
                        if lifecycle_rules is not None:
                            for rule in lifecycle_rules:
                                if "Expiration" in rule and "Days" in rule["Expiration"]:
                                    days = rule["Expiration"]["Days"]
                                    if retention is None or days < retention:
                                        retention = days

                        retention = retention if retention is not None else "Never Expire"
                        cloudtrail_buckets.append(
                            f"Trail: {trail.get('Name', 'Unknown')} -> "
                            f"{bucket_name} (Account: {bucket_account}, days) -> {retention}"
                        )
                    else:
                        # Add debug logging for missing buckets
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
                        f"\nAccount: {account}, Region: {region}\nCloudTrail Logging Buckets:"
                    )
                    for bucket in sorted(cloudtrail_buckets):
                        cloudtrail_buckets_by_retention.append(f"  - {bucket}")

            # Process Route53 Resolver query log configs
            if resolver_configs:
                resolver_buckets = []
                for rc in resolver_configs:
                    destination = rc.get("DestinationArn", "")
                    if destination.startswith("arn:aws:s3:::"):
                        # Extract bucket name from ARN
                        bucket_name = destination.split(":::")[1].split("/")[0]
                        if bucket_name in all_buckets:
                            bucket, bucket_account = all_buckets[bucket_name]
                            # Find the shortest expiration period in lifecycle rules
                            retention = None
                            lifecycle_rules = bucket.get("LifecycleRules")
                            if lifecycle_rules is not None:
                                for rule in lifecycle_rules:
                                    if "Expiration" in rule and "Days" in rule["Expiration"]:
                                        days = rule["Expiration"]["Days"]
                                        if retention is None or days < retention:
                                            retention = days

                            retention = retention if retention is not None else "Never Expire"
                            resolver_buckets.append(
                                f"Config: {rc.get('Name', 'Unknown')} -> "
                                f"{bucket_name} (Account: {bucket_account}, days) -> {retention}"
                            )
                        else:
                            resolver_buckets.append(
                                f"Config: {rc.get('Name', 'Unknown')} -> "
                                f"{bucket_name} (bucket not found in any account)"
                            )

                if resolver_buckets:
                    resolver_logs_by_retention.append(
                        f"\nAccount: {account}, Region: {region}\nRoute53 Resolver Query Log Configs:"
                    )
                    for bucket in sorted(resolver_buckets):
                        resolver_logs_by_retention.append(f"  - {bucket}")

            # Process VPC flow logs
            if flow_logs:
                flow_log_buckets = []
                for flow_log in flow_logs:
                    if flow_log.get("LogDestinationType") == "s3":
                        destination = flow_log.get("LogDestination", "")
                        if destination:
                            # Extract bucket name from ARN
                            bucket_name = destination.split(":::")[1].split("/")[0]
                            if bucket_name in all_buckets:
                                bucket, bucket_account = all_buckets[bucket_name]
                                # Find the shortest expiration period in lifecycle rules
                                retention = None
                                lifecycle_rules = bucket.get("LifecycleRules")
                                if lifecycle_rules is not None:
                                    for rule in lifecycle_rules:
                                        if "Expiration" in rule and "Days" in rule["Expiration"]:
                                            days = rule["Expiration"]["Days"]
                                            if retention is None or days < retention:
                                                retention = days

                                retention = retention if retention is not None else "Never Expire"
                                flow_log_buckets.append(
                                    f"Flow Log: {flow_log.get('FlowLogId', 'Unknown')} -> "
                                    f"{bucket_name} (Account: {bucket_account}, days) -> {retention}"
                                )
                            else:
                                flow_log_buckets.append(
                                    f"Flow Log: {flow_log.get('FlowLogId', 'Unknown')} -> "
                                    f"{bucket_name} (bucket not found in any account)"
                                )

                if flow_log_buckets:
                    flow_logs_by_retention.append(
                        f"\nAccount: {account}, Region: {region}\nVPC Flow Logs:"
                    )
                    for bucket in sorted(flow_log_buckets):
                        flow_logs_by_retention.append(f"  - {bucket}")

    # Build the message
    message = (
        "This check verifies that logs are retained for a suitable period.\n\n"
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
        + "\n\nPlease review the retention periods above and consider:\n"
        "- Are logs retained for as long as required by security requirements?\n"
        "- Are logs retained for longer than necessary?"
    )

    # Use manual_check to get user confirmation
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt="Are logs retained for a suitable period?",
        pass_message="Logs are retained for a suitable period",
        fail_message="Log retention settings need to be reviewed",
        default=True,
    )


# Attach the check ID and name to the function
check_log_retention._CHECK_ID = CHECK_ID
check_log_retention._CHECK_NAME = CHECK_NAME
