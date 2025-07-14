"""Check for use of hardened images with security controls."""

from typing import Any

from kite.helpers import manual_check

CHECK_ID = "use-hardened-images"
CHECK_NAME = "Use Hardened Images"


def check_use_hardened_images() -> dict[str, Any]:
    """
    Check if compute is provisioned from hardened images, applying controls such as
    those from the Center for Internet Security (CIS) and the Defense Information
    Systems Agency (DISA) Security Technical Implementation Guides (STIGs).

    This check asks the user to confirm that:
    1. Compute instances are provisioned from hardened images
    2. The hardened images apply security controls from CIS benchmarks
    3. The hardened images apply security controls from DISA STIGs
    4. The hardened images are regularly updated and maintained

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that compute is provisioned from hardened images, "
        "applying controls such as those from the Center for Internet Security "
        "(CIS) and the Defense Information Systems Agency (DISA) Security "
        "Technical Implementation Guides (STIGs).\n\n"
        "Consider the following factors:\n"
        "- Are compute instances provisioned from hardened images?\n"
        "- Do the hardened images apply security controls from CIS benchmarks?\n"
        "- Do the hardened images apply security controls from DISA STIGs?\n"
        "- Are the hardened images regularly updated and maintained?\n"
        "- Are the hardened images validated and tested before deployment?\n"
        "- Is there a process for creating and maintaining hardened images?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is compute provisioned from hardened images, applying controls such as "
            "those from CIS and DISA STIGs?"
        ),
        pass_message=(
            "Compute is provisioned from hardened images with appropriate security "
            "controls from CIS and DISA STIGs."
        ),
        fail_message=(
            "Compute should be provisioned from hardened images with appropriate "
            "security controls from CIS and DISA STIGs."
        ),
        default=True,
    )


check_use_hardened_images._CHECK_ID = CHECK_ID
check_use_hardened_images._CHECK_NAME = CHECK_NAME
