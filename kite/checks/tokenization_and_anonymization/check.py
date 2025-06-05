"""Tokenization and anonymization check."""

from kite.helpers import manual_check

CHECK_ID = "tokenization-and-anonymization"
CHECK_NAME = "Tokenization and anonymization techniques"


def check_tokenization_and_anonymization() -> dict[str, object]:
    """Check if tokenization and anonymization techniques are used appropriately.

    This check verifies that techniques such as tokenization and anonymization are
    used to reduce data sensitivity levels where appropriate.
    """
    message = (
        "This check verifies that appropriate techniques are used to reduce data "
        "sensitivity levels.\n\n"
        "Consider the following:\n"
        "- Are tokenization techniques used to replace sensitive data with "
        "non-sensitive tokens?\n"
        "- Is anonymization applied to remove or mask personally identifiable "
        "information?\n"
        "- Is there a process to evaluate when tokenization or anonymization should "
        "be applied?"
    )

    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        prompt=(
            "Are tokenization and anonymization techniques used to reduce data "
            "sensitivity levels where appropriate?"
        ),
        pass_message=(
            "Tokenization and anonymization techniques are used appropriately."
        ),
        fail_message=(
            "Tokenization and anonymization techniques are not used appropriately."
        ),
        message=message,
        default=True,
    )
