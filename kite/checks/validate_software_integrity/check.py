"""Check for software integrity validation using cryptographic signatures."""

from typing import Dict, Any

from kite.helpers import manual_check


CHECK_ID = "validate-software-integrity"
CHECK_NAME = "Validate Software Integrity"


def check_validate_software_integrity() -> Dict[str, Any]:
    """
    Check if the integrity of software is validated using cryptographic signatures
    where available, and that published artifacts are cryptographically signed.

    This check asks the user to confirm that:
    1. Software integrity is validated using cryptographic signatures where available
    2. Published artifacts are cryptographically signed
    3. Signature verification is performed before deployment or execution

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    message = (
        "This check verifies that the integrity of software is validated using "
        "cryptographic signatures where available, and that published artifacts "
        "are cryptographically signed.\n\n"
        "Consider the following factors:\n"
        "- Are software packages validated using cryptographic signatures "
        "before installation?\n"
        "- Are container images signed and verified before deployment?\n"
        "- Are application artifacts signed?\n"
        "- Are third-party dependencies validated for integrity?\n"
        "- Are signing keys properly managed and rotated?\n"
        "- Is signature verification automated in CI/CD pipelines?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=(
            "Is the integrity of software validated using cryptographic "
            "signatures where available, and are published artifacts "
            "cryptographically signed?"
        ),
        pass_message=(
            "Software integrity is validated using cryptographic signatures "
            "and published artifacts are cryptographically signed."
        ),
        fail_message=(
            "Software integrity should be validated using cryptographic "
            "signatures and published artifacts should be cryptographically signed."
        ),
        default=True,
    )


check_validate_software_integrity._CHECK_ID = CHECK_ID
check_validate_software_integrity._CHECK_NAME = CHECK_NAME
