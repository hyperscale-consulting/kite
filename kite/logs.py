from typing import Any

import boto3


def get_log_groups(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """Get all log groups in the account."""
    logs = session.client("logs", region_name=region)
    paginator = logs.get_paginator("describe_log_groups")
    log_groups = []
    for page in paginator.paginate():
        log_groups.extend(page.get("logGroups", []))
    return log_groups


def get_export_tasks(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """Get all export tasks in the account."""
    logs = session.client("logs", region_name=region)
    paginator = logs.get_paginator("describe_export_tasks")
    export_tasks = []
    for page in paginator.paginate():
        export_tasks.extend(page.get("exportTasks", []))
    return export_tasks
