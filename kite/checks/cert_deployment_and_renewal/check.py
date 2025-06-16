"""Check for automated certificate deployment and renewal."""

from typing import Dict, Any, List

from kite.helpers import manual_check, get_account_ids_in_scope
from kite.data import get_acm_certificates
from kite.config import Config


CHECK_ID = "automate-cert-deployment-and-renewal"
CHECK_NAME = "Automate Certificate Deployment and Renewal"


def analyze_certificate_renewal_status() -> tuple[
    List[Dict[str, Any]], List[Dict[str, Any]]
]:
    """
    Analyze ACM certificates for renewal eligibility.

    Returns:
        Tuple containing:
            - List of certificates eligible for auto-renewal
            - List of certificates not eligible for auto-renewal
    """
    eligible_certs = []
    ineligible_certs = []

    # Get all accounts in scope
    account_ids = get_account_ids_in_scope()

    # Check certificates in each account and region
    for account_id in account_ids:
        for region in Config.get().active_regions:
            certificates = get_acm_certificates(account_id, region)

            for cert in certificates:
                # Check if certificate meets all criteria for auto-renewal
                is_eligible = (
                    cert.get("RenewalEligibility") == "ELIGIBLE" and
                    any(
                        opt.get("ValidationMethod") == "DNS"
                        for opt in cert.get("DomainValidationOptions", [])
                    ) and
                    cert.get("InUseBy", [])
                )

                # Add account and region info to certificate
                cert_info = {
                    "CertificateArn": cert.get("CertificateArn"),
                    "DomainName": cert.get("DomainName"),
                    "Status": cert.get("Status"),
                    "AccountId": account_id,
                    "Region": region
                }

                if is_eligible:
                    eligible_certs.append(cert_info)
                else:
                    ineligible_certs.append(cert_info)

    return eligible_certs, ineligible_certs


def check_cert_deployment_and_renewal() -> Dict[str, Any]:
    """
    Check if certificate deployment and renewal is automated.

    Returns:
        Dict containing:
            - check_id: str identifying the check
            - check_name: str name of the check
            - status: str indicating if the check passed ("PASS", "FAIL", or "ERROR")
            - details: Dict containing:
                - message: str describing the result
    """
    # Get certificate renewal status
    eligible_certs, ineligible_certs = analyze_certificate_renewal_status()

    # Build the message with certificate information
    message = (
        "This check verifies that certificate deployment and renewal is automated for "
        "public and private certificates.\n\n"
    )

    if eligible_certs:
        message += "Certificates configured for automatic renewal:\n"
        for cert in eligible_certs:
            message += (
                f"- {cert['DomainName']} (Account: {cert['AccountId']}, "
                f"Region: {cert['Region']})\n"
            )
        message += "\n"

    if ineligible_certs:
        message += "Certificates not configured for automatic renewal:\n"
        for cert in ineligible_certs:
            message += (
                f"- {cert['DomainName']} (Account: {cert['AccountId']}, "
                f"Region: {cert['Region']})\n"
            )
        message += "\n"

    if not eligible_certs and not ineligible_certs:
        message += "No ACM certificates found in any account or region.\n\n"

    message += (
        "An ACM certificate is considered eligible for automatic renewal if:\n"
        "- RenewalEligibility is 'ELIGIBLE'\n"
        "- DomainValidationOptions.ValidationMethod is 'DNS'\n"
        "- InUseBy list is non-empty\n\n"
    )

    message += (
        "Please also consider any public or private certificates issues outside of "
        "ACM.\n"
    )

    prompt = (
        "Is certificate deployment and renewal automated?"
    )

    # Use the manual_check function
    result = manual_check(
        check_id=CHECK_ID,
        check_name=CHECK_NAME,
        message=message,
        prompt=prompt,
        pass_message=(
            "Certificate deployment and renewal is automated."
        ),
        fail_message=(
            "Certificate deployment and renewal should be automated."
        ),
        default=True,
    )

    return result


check_cert_deployment_and_renewal._CHECK_ID = CHECK_ID
check_cert_deployment_and_renewal._CHECK_NAME = CHECK_NAME
