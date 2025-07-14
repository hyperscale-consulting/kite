"""Check for CI/CD pipeline threat modeling."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "threat-model-pipelines"
CHECK_NAME = "Pipeline Threat Modeling"


def check_threat_model_pipelines() -> dict[str, Any]:
    """
    Check if CI/CD pipelines are threat modeled in the same way as other production
    workloads to identify and address risks to the software supply chain.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that CI/CD pipelines are threat modeled in the same "
        "way as other production workloads to identify and address risks to the "
        "software supply chain.\n\n"
        "Consider the following factors:\n"
        "- Are CI/CD pipelines included in threat modeling exercises?\n"
        "- Are software supply chain risks identified and addressed?"
    )
    prompt = (
        "Are CI/CD pipelines threat modeled in the same way as other production "
        "workloads to identify and address risks to the software supply chain?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "CI/CD pipelines are threat modeled in the same way as other production "
            "workloads to identify and address risks to the software supply chain."
        ),
        fail_message=(
            "CI/CD pipelines should be threat modeled in the same way as other "
            "production workloads to identify and address risks to the software "
            "supply chain."
        ),
        default=True,
    )


check_threat_model_pipelines._CHECK_ID = CHECK_ID
check_threat_model_pipelines._CHECK_NAME = CHECK_NAME
