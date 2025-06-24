"""Check for no RDP or SSH access exposed to internet."""

from typing import Dict, Any, List

from kite.helpers import get_prowler_output


CHECK_ID = "no-rdp-or-ssh-access"
CHECK_NAME = "No RDP or SSH Access Exposed to Internet"


def check_no_rdp_or_ssh_access() -> Dict[str, Any]:
    """
    Check if RDP or SSH ports are exposed to the internet.

    This check verifies that RDP and SSH ports are not exposed to the internet
    by checking Prowler results for the following check IDs:
    - ec2_instance_port_rdp_exposed_to_internet
    - ec2_instance_port_ssh_exposed_to_internet

    The check fails if any of these checks fail, indicating that RDP or SSH
    ports are exposed to the internet.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
                - failing_resources: List of resources that failed the check
    """
    # Get Prowler results
    prowler_results = get_prowler_output()

    # The check IDs we're interested in
    check_ids = [
        "ec2_instance_port_rdp_exposed_to_internet",
        "ec2_instance_port_ssh_exposed_to_internet",
    ]

    # Track failing resources
    failing_resources: List[Dict[str, Any]] = []

    # Check results for each check ID
    for check_id in check_ids:
        if check_id in prowler_results:
            # Get results for this check ID
            results = prowler_results[check_id]

            # Add failing resources to the list
            for result in results:
                if result.status != "PASS":
                    failing_resources.append({
                        "account_id": result.account_id,
                        "resource_uid": result.resource_uid,
                        "resource_name": result.resource_name,
                        "resource_details": result.resource_details,
                        "region": result.region,
                        "status": result.status,
                        "check_id": check_id
                    })

    # Determine if the check passed
    passed = len(failing_resources) == 0

    return {
        "check_id": CHECK_ID,
        "check_name": CHECK_NAME,
        "status": "PASS" if passed else "FAIL",
        "details": {
            "message": (
                "No RDP or SSH ports are exposed to the internet."
                if passed
                else (
                    f"Found {len(failing_resources)} EC2 instances with RDP or SSH "
                    "ports exposed to the internet."
                )
            ),
            "failing_resources": failing_resources,
        },
    }


# Attach the check ID and name to the function
check_no_rdp_or_ssh_access._CHECK_ID = CHECK_ID
check_no_rdp_or_ssh_access._CHECK_NAME = CHECK_NAME
