import boto3


def get_maintenance_windows(
    session: boto3.Session,
    region: str,
) -> list[dict[str, object]]:
    """
    Get the maintenance windows for a given account and region.
    """
    client = session.client("ssm", region_name=region)
    paginator = client.get_paginator("describe_maintenance_windows")
    maintenance_windows = []
    for page in paginator.paginate():
        for mw in page["WindowIdentities"]:
            mw["Targets"] = get_maintenance_window_targets(
                session, region, mw["WindowId"]
            )
            mw["Tasks"] = get_maintenance_window_tasks(session, region, mw["WindowId"])
            maintenance_windows.append(mw)
    return maintenance_windows


def get_maintenance_window_targets(
    session: boto3.Session,
    region: str,
    window_id: str,
) -> list[dict[str, object]]:
    """
    Get the targets for a given maintenance window.
    """
    client = session.client("ssm", region_name=region)
    paginator = client.get_paginator("describe_maintenance_window_targets")
    targets = []
    for page in paginator.paginate(WindowId=window_id):
        targets.extend(page["Targets"])
    return targets


def get_maintenance_window_tasks(
    session: boto3.Session,
    region: str,
    window_id: str,
) -> list[dict[str, object]]:
    """
    Get the tasks for a given maintenance window.
    """
    client = session.client("ssm", region_name=region)
    paginator = client.get_paginator("describe_maintenance_window_tasks")
    tasks = []
    for page in paginator.paginate(WindowId=window_id):
        tasks.extend(page["Tasks"])
    return tasks
