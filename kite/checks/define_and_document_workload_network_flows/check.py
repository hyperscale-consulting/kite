"""Check for defining and documenting workload network flows."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "define-and-document-workload-network-flows"
CHECK_NAME = "Define and Document Workload Network Flows"


def check_define_and_document_workload_network_flows() -> dict[str, Any]:
    """
    Check if workload network flows have been defined and documented in a data flow
    diagram.


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
        "This check verifies that workload network flows have been defined and "
        "documented in a data flow diagram.\n\n"
        "Consider the following factors:\n"
        "- Are all network flows between components clearly defined?\n"
        "- Are data flow diagrams up to date and maintained?"
    )
    prompt = (
        "Have workload network flows been defined and documented in a data flow "
        "diagram?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Workload network flows are well-defined and documented in data flow "
            "diagrams."
        ),
        fail_message=(
            "Workload network flows should be defined and documented in data flow "
            "diagrams."
        ),
        default=True,
    )

    return result


check_define_and_document_workload_network_flows._CHECK_ID = CHECK_ID
check_define_and_document_workload_network_flows._CHECK_NAME = CHECK_NAME
