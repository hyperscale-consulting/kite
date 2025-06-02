import boto3


def get_graphs(session: boto3.Session, region: str) -> list[dict[str, object]]:
    client = session.client("detective", region_name=region)
    response = client.list_graphs()
    graphs = []
    for graph in response["GraphList"]:
        arn = graph["Arn"]
        members = get_members(client, arn)
        graph["Members"] = members
        graphs.append(graph)
    return graphs


def get_members(client, arn: str) -> list[dict[str, object]]:
    response = client.list_members(GraphArn=arn)
    members = []
    for member in response["MemberDetails"]:
        members.append(member)
    return members
