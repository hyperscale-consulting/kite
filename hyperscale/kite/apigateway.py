import boto3


def get_rest_apis(session: boto3.Session, region: str) -> list[dict[str, object]]:
    client = session.client("apigateway", region_name=region)
    paginator = client.get_paginator("get_rest_apis")
    rest_apis = []
    for page in paginator.paginate():
        rest_apis.extend(page["items"])
    return rest_apis
