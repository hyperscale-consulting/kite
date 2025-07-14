"""Check for workload and dependency update mechanisms."""

from kite.helpers import manual_check

CHECK_ID = "workload-dependency-updates"
CHECK_NAME = "Workload and Dependency Updates"


def check_workload_dependency_updates():
    """Check if mechanisms are in place to quickly and safely update workloads and
    dependencies to latest available versions that provide known threat mitigations.

    Returns:
        dict: A dictionary containing the check results.
    """
    return manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=(
            "Are mechanisms in place to quickly and safely "
            "update workloads and dependencies to latest available versions that "
            "provide known threat mitigations.\n\n"
            "Consider the following factors:\n"
            "- Are teams automatically notified as soon as vulnerable components are "
            "detected?\n"
            "- Do teams have mechanisms (e.g. automated test suites) that can quickly "
            "provide confidence in updated workloads?\n"
            "- Do teams have automated processes for updating workloads?"
        ),
        prompt=(
            "Are mechanisms in place to quickly and safely update workloads and "
            "dependencies to latest available versions that provide known threat "
            "mitigations?"
        ),
        pass_message=(
            "Teams have established mechanisms for quickly and safely updating "
            "workloads and dependencies to mitigate known threats."
        ),
        fail_message=(
            "Teams lack mechanisms for quickly and safely updating workloads and "
            "dependencies to mitigate known threats."
        ),
        default=True,
    )


# Attach the check ID and name to the function
check_workload_dependency_updates._CHECK_ID = CHECK_ID
check_workload_dependency_updates._CHECK_NAME = CHECK_NAME
