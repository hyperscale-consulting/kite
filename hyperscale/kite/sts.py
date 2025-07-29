import boto3


def assume_role(account_id: str, role_name: str, external_id: str):
    sts_client = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    assumed_role = sts_client.assume_role(
        RoleArn=role_arn, RoleSessionName="KiteAssessment", ExternalId=external_id
    )

    return boto3.Session(
        aws_access_key_id=assumed_role["Credentials"]["AccessKeyId"],
        aws_secret_access_key=assumed_role["Credentials"]["SecretAccessKey"],
        aws_session_token=assumed_role["Credentials"]["SessionToken"],
    )
