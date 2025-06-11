def get_backup_vaults(session, region) -> list[dict]:
    client = session.client("backup", region_name=region)
    paginator = client.get_paginator("list_backup_vaults")
    vaults = []
    for page in paginator.paginate():
        for vault in page["BackupVaultList"]:
            vaults.append(vault)

    return vaults


def get_protected_resources(session, region) -> list[dict]:
    client = session.client("backup", region_name=region)
    paginator = client.get_paginator("list_protected_resources")
    resources = []
    for page in paginator.paginate():
        for resource in page["Results"]:
            resources.append(resource)

    return resources
