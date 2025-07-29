import boto3


def get_graphql_apis(session: boto3.Session, region: str) -> list[dict[str, object]]:
    client = session.client("appsync", region_name=region)
    paginator = client.get_paginator("list_graphql_apis")
    graphql_apis = []
    for page in paginator.paginate():
        graphql_apis.extend(page["graphqlApis"])
    return graphql_apis
