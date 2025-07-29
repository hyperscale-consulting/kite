from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.config import Config
from hyperscale.kite.data import get_acm_certificates
from hyperscale.kite.helpers import get_account_ids_in_scope


class CertDeploymentAndRenewalCheck:
    def __init__(self):
        self.check_id = "automate-cert-deployment-and-renewal"
        self.check_name = "Automate Certificate Deployment and Renewal"

    @property
    def question(self) -> str:
        return (
            "Is certificate deployment and renewal automated for public and private "
            "certificates?"
        )

    @property
    def description(self) -> str:
        return (
            "This check verifies that certificate deployment and renewal is automated "
            "for public and private certificates."
        )

    def _analyze_certificate_renewal_status(self):
        eligible_certs = []
        ineligible_certs = []
        account_ids = get_account_ids_in_scope()
        for account_id in account_ids:
            for region in Config.get().active_regions:
                certificates = get_acm_certificates(account_id, region)
                for cert in certificates:
                    is_eligible = (
                        cert.get("RenewalEligibility") == "ELIGIBLE"
                        and any(
                            opt.get("ValidationMethod") == "DNS"
                            for opt in cert.get("DomainValidationOptions", [])
                        )
                        and cert.get("InUseBy", [])
                    )
                    cert_info = {
                        "CertificateArn": cert.get("CertificateArn"),
                        "DomainName": cert.get("DomainName"),
                        "Status": cert.get("Status"),
                        "AccountId": account_id,
                        "Region": region,
                    }
                    if is_eligible:
                        eligible_certs.append(cert_info)
                    else:
                        ineligible_certs.append(cert_info)
        return eligible_certs, ineligible_certs

    def run(self) -> CheckResult:
        eligible_certs, ineligible_certs = self._analyze_certificate_renewal_status()
        message = ""
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
        return CheckResult(
            status=CheckStatus.MANUAL,
            context=message,
            details={
                "eligible_certs": eligible_certs,
                "ineligible_certs": ineligible_certs,
            },
        )
