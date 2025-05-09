"""Check for technology inventory scanning."""


# TODO: automated support for this check - required addition permissions

from kite.helpers import manual_check


CHECK_ID = "tech-inventories-scanned"
CHECK_NAME = "Technology Inventory Scanning"


def check_tech_inventories_scanned():
    """Check if teams maintain inventories of technology components and continuously
    scan them for potential vulnerabilities.

    Returns:
        dict: A dictionary containing the check results.
    """
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=(
            "Do teams maintain inventories of technology "
            "components and continuously scan them for potential vulnerabilities.\n\n"
            "Consider the following factors:\n"
            "- Do teams maintain up-to-date inventories of all technology "
            "components (e.g. SBOMs)?\n"
            "- Are these inventories regularly scanned for vulnerabilities (e.g. "
            "Inspector, ECR scanning)?"
        ),
        prompt=(
            "Do teams maintain inventories of technology components and continuously "
            "scan them for potential vulnerabilities?"
        ),
        pass_message=(
            "Teams maintain comprehensive technology inventories and regularly scan "
            "them for vulnerabilities."
        ),
        fail_message=(
            "Teams do not maintain complete technology inventories or do not "
            "regularly scan them for vulnerabilities."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_tech_inventories_scanned._CHECK_ID = CHECK_ID
check_tech_inventories_scanned._CHECK_NAME = CHECK_NAME
