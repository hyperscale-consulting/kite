"""SageMaker service module for Kite."""

from dataclasses import dataclass


@dataclass
class SageMakerNotebook:
    """SageMaker notebook instance data class."""

    notebook_name: str
    region: str


def get_notebook_instances(session, region: str) -> list[SageMakerNotebook]:
    """
    Get all SageMaker notebook instances in a region.

    Args:
        session: The boto3 session to use
        region: The AWS region to check

    Returns:
        List of SageMaker notebook instances
    """
    sagemaker_client = session.client("sagemaker", region_name=region)
    notebooks = []

    response = sagemaker_client.list_notebook_instances()
    for instance in response.get("NotebookInstances", []):
        notebooks.append(
            SageMakerNotebook(
                notebook_name=instance.get("NotebookInstanceName"),
                region=region,
            )
        )

    return notebooks
