import boto3


def get_file_systems(session: boto3.Session, region: str) -> list[dict[str, object]]:
    client = session.client("efs", region_name=region)
    paginator = client.get_paginator("describe_file_systems")
    file_systems = []
    for page in paginator.paginate():
        for file_system in page["FileSystems"]:
            file_system["MountTargets"] = _get_mount_targets(
                client, file_system["FileSystemId"]
            )
            file_systems.append(file_system)
    return file_systems


def _get_mount_targets(client, file_system_id: str) -> list[dict[str, object]]:
    paginator = client.get_paginator("describe_mount_targets")
    mount_targets = []
    for page in paginator.paginate(FileSystemId=file_system_id):
        for mount_target in page["MountTargets"]:
            mount_target["SecurityGroups"] = _get_security_groups(
                client, mount_target["MountTargetId"]
            )
            mount_targets.append(mount_target)
    return mount_targets


def _get_security_groups(client, mount_target_id: str) -> list[dict[str, object]]:
    response = client.describe_mount_target_security_groups(
        MountTargetId=mount_target_id
    )
    return response["SecurityGroups"]
