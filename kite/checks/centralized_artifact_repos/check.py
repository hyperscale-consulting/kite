"""Check for use of centralized artifact repositories."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "use-centralized-artifact-repos"
CHECK_NAME = "Use Centralized Artifact Repositories"


def check_use_centralized_artifact_repos() -> dict[str, Any]:
    """
    Check if centralized artifact repositories are used to mitigate threats such as
    dependency confusion attacks.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    # Define the message and prompts
    message = (
        "This check verifies that centralized artifact repositories are used to "
        "mitigate threats such as dependency confusion and typosquatting attacks.\n\n"
        "Consider the following factors:\n"
        "- Are artifact repositories (e.g., npm, PyPI, Maven) hosted internally?\n"
        "- Are packages validated before use?\n"
        "- Is the use of vulnerable / malicious packages detected and remediated, or "
        "prevented?"
    )
    prompt = (
        "Are centralized artifact repositories used to mitigate threats such as "
        "dependency confusion attacks?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Centralized artifact repositories are used to mitigate threats such as "
            "dependency confusion attacks."
        ),
        fail_message=(
            "Centralized artifact repositories should be used to mitigate threats such "
            "as dependency confusion attacks."
        ),
        default=True,
    )

    return result


check_use_centralized_artifact_repos._CHECK_ID = CHECK_ID
check_use_centralized_artifact_repos._CHECK_NAME = CHECK_NAME
