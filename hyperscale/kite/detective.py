import boto3
from botocore.exceptions import ClientError


def get_graphs(session: boto3.Session, region: str) -> list[dict[str, object]]:
    client = session.client("detective", region_name=region)
    try:
        response = client.list_graphs()
        graphs = []
        for graph in response["GraphList"]:
            arn = graph["Arn"]
            members = get_members(client, arn)
            graph["Members"] = members
            graphs.append(graph)
        return graphs
    except ClientError as e:
        if e.response["Error"]["Code"] == "SubscriptionRequiredException":
            return []
        raise e


def get_members(client, arn: str) -> list[dict[str, object]]:
    response = client.list_members(GraphArn=arn)
    members = []
    for member in response["MemberDetails"]:
        members.append(member)
    return members
