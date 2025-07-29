from typing import Any

import boto3


def list_analyzers(session: boto3.Session) -> list[dict[str, Any]]:
    """List all Access Analyzer analyzers.

    Args:
        session: The AWS session.

    Returns:
        The list of Access Analyzer analyzers.
    """
    access_analyzer = session.client("accessanalyzer")
    analyzers = []
    for analyzer in access_analyzer.list_analyzers()["analyzers"]:
        analyzers.append(
            access_analyzer.get_analyzer(analyzerName=analyzer["name"])["analyzer"]
        )
    return analyzers
