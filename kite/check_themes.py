"""Check themes module for Kite."""

from collections.abc import Callable

from kite.checks import AccessManagementLifecycleCheck
from kite.checks import AccessManagementLifecycleImplementedCheck
from kite.checks import AccountStandardsCheck
from kite.checks import ApprovalProcessForResourceSharingCheck
from kite.checks import automate_malware_and_threat_detection
from kite.checks import AutomateDeploymentsCheck
from kite.checks import AutomatedSecurityTestsCheck
from kite.checks import AutomateForensicsCheck
from kite.checks import AwsControlDocumentationCheck
from kite.checks import AwsManagedServicesThreatIntelCheck
from kite.checks import AwsServiceEvaluationCheck
from kite.checks import CaptureKeyContactsCheck
from kite.checks import CentralizedArtifactReposCheck
from kite.checks import Check
from kite.checks import check_account_separation
from kite.checks import check_accurate_account_contact_details
from kite.checks import check_active_external_access_analyzer
from kite.checks import check_active_unused_access_analyzer
from kite.checks import check_admin_privileges_are_restricted
from kite.checks import check_air_gapped_backup_vault
from kite.checks import check_api_gateway_logging_enabled
from kite.checks import check_audit_interactive_access_with_ssm
from kite.checks import check_auto_remediate_non_compliant_resources
from kite.checks import check_automate_data_at_rest_protection_with_guardduty
from kite.checks import check_automate_ddb_data_retention
from kite.checks import check_automate_patch_management
from kite.checks import check_automate_s3_data_retention
from kite.checks import check_avoid_insecure_ssl_ciphers
from kite.checks import check_avoid_interactive_access
from kite.checks import check_aws_organizations_usage
from kite.checks import check_cert_deployment_and_renewal
from kite.checks import check_cloudfront_logging_enabled
from kite.checks import check_complex_passwords
from kite.checks import check_config_recording_enabled
from kite.checks import check_control_network_flow_with_nacls
from kite.checks import check_control_network_flows_with_route_tables
from kite.checks import check_control_network_flows_with_sgs
from kite.checks import check_controls_implemented_based_on_sensitivity
from kite.checks import check_create_network_layers
from kite.checks import check_credential_rotation
from kite.checks import check_cross_account_confused_deputy_prevention
from kite.checks import check_cw_data_protection_policies
from kite.checks import check_data_perimeter_confused_deputy_protection
from kite.checks import check_data_perimeter_trusted_networks
from kite.checks import check_data_perimeter_trusted_resources
from kite.checks import check_delegate_iam_with_permission_boundaries
from kite.checks import check_delegated_admins_security_services
from kite.checks import check_deploy_log_analysis_tools_in_audit_account
from kite.checks import check_detect_encryption_at_rest_misconfig
from kite.checks import check_detect_missing_automated_lifecycle_management
from kite.checks import check_detect_sensitive_data_transform
from kite.checks import check_detective_enabled
from kite.checks import check_eks_control_plane_logging_enabled
from kite.checks import check_elb_logging_enabled
from kite.checks import check_enforce_https
from kite.checks import check_establish_data_perimeter_trusted_identities
from kite.checks import check_forensics_ou
from kite.checks import check_hr_system_integration
from kite.checks import check_implement_versioning_and_object_locking
from kite.checks import check_inspect_http_traffic_with_waf
from kite.checks import check_inspect_traffic_with_network_firewall
from kite.checks import check_isolation_boundaries
from kite.checks import check_key_access_control
from kite.checks import check_kms_confused_deputy_protection
from kite.checks import check_lambda_confused_deputy_protection
from kite.checks import check_limit_access_to_production_environments
from kite.checks import check_log_alerting
from kite.checks import check_log_retention
from kite.checks import check_management_account_workloads
from kite.checks import check_migrate_from_oai
from kite.checks import check_monitor_and_response_to_s3_public_access
from kite.checks import check_network_firewall_logging_enabled
from kite.checks import check_no_access_keys
from kite.checks import check_no_full_access_to_sensitive_services
from kite.checks import check_no_full_admin_policies
from kite.checks import check_no_human_access_to_unencrypted_key_material
from kite.checks import check_no_iam_user_access
from kite.checks import check_no_key_pairs
from kite.checks import check_no_permissive_role_assumption
from kite.checks import check_no_policy_allows_privilege_escalation
from kite.checks import check_no_rdp_or_ssh_access
from kite.checks import check_no_readonly_third_party_access
from kite.checks import check_no_root_access_keys
from kite.checks import check_no_secrets_in_aws_resources
from kite.checks import check_organizational_cloudtrail
from kite.checks import check_ou_structure
from kite.checks import check_protect_root_ca
from kite.checks import check_rds_logging_enabled
from kite.checks import check_region_deny_scp
from kite.checks import check_repeatable_auditable_setup_for_3rd_party_access
from kite.checks import check_require_mfa
from kite.checks import check_restore_testing
from kite.checks import check_restricted_role_for_secrets_access
from kite.checks import check_review_pipeline_permissions_regularly
from kite.checks import check_root_access_keys_disallowed
from kite.checks import check_root_access_testing
from kite.checks import check_root_account_monitoring
from kite.checks import check_root_credentials_management_enabled
from kite.checks import check_root_credentials_security
from kite.checks import check_root_mfa_enabled
from kite.checks import check_root_user_usage
from kite.checks import check_rotate_encryption_keys
from kite.checks import check_run_simulations
from kite.checks import check_s3_bucket_acl_disabled
from kite.checks import check_s3_confused_deputy_protection
from kite.checks import check_scan_for_sensitive_data_in_dev
from kite.checks import check_scan_workloads_for_vulnerabilities
from kite.checks import check_scim_protocol_used
from kite.checks import check_scp_prevents_adding_internet_access_to_vpc
from kite.checks import check_scp_prevents_cloudwatch_changes
from kite.checks import check_scp_prevents_common_admin_role_changes
from kite.checks import check_scp_prevents_config_changes
from kite.checks import check_scp_prevents_deleting_logs
from kite.checks import check_scp_prevents_guardduty_changes
from kite.checks import check_scp_prevents_leaving_org
from kite.checks import check_scp_prevents_ram_external_sharing
from kite.checks import check_scp_prevents_ram_invitations
from kite.checks import check_scp_prevents_unencrypted_s3_uploads
from kite.checks import check_secure_secrets_storage
from kite.checks import check_security_data_published_to_log_archive_account
from kite.checks import check_security_event_correlation
from kite.checks import check_security_guardians_program
from kite.checks import check_security_ir_playbooks
from kite.checks import check_security_risks
from kite.checks import check_security_services_evaluation
from kite.checks import check_service_catalog
from kite.checks import check_sns_confused_deputy_protection
from kite.checks import check_sns_data_protection_policies
from kite.checks import check_sqs_confused_deputy_protection
from kite.checks import check_tag_data_with_sensitivity_level
from kite.checks import check_tech_inventories_scanned
from kite.checks import check_threat_intelligence_monitoring
from kite.checks import check_threat_model_pipelines
from kite.checks import check_threat_modeling
from kite.checks import check_tokenization_and_anonymization
from kite.checks import check_train_for_application_security
from kite.checks import check_trusted_delegated_admins
from kite.checks import check_use_a_kms
from kite.checks import check_use_centralized_idp
from kite.checks import check_use_customer_managed_keys
from kite.checks import check_use_hardened_images
from kite.checks import check_use_identity_broker
from kite.checks import check_use_of_higher_level_services
from kite.checks import check_use_private_link_for_vpc_routing
from kite.checks import check_use_route53resolver_dns_firewall
from kite.checks import check_use_service_encryption_at_rest
from kite.checks import check_validate_software_integrity
from kite.checks import check_vpc_endpoints_enforce_data_perimeter
from kite.checks import check_vpc_flow_logs_enabled
from kite.checks import check_waf_web_acl_logging_enabled
from kite.checks import check_well_defined_control_objectives
from kite.checks import check_workload_dependency_updates
from kite.checks import CodeReviewsCheck
from kite.checks import ControlImplementationValidationCheck
from kite.checks import ControlTowerCheck
from kite.checks import DataCatalogCheck
from kite.checks import DefineAccessRequirementsCheck
from kite.checks import DefineAndDocumentWorkloadNetworkFlowsCheck
from kite.checks import DfdsCheck
from kite.checks import DocumentedDataClassificationSchemeCheck
from kite.checks import EmployUserGroupsAndAttributesCheck
from kite.checks import EnforceDataProtectionAtRestWithPolicyAsCodeCheck
from kite.checks import EstablishedEmergencyAccessProceduresCheck
from kite.checks import EstablishLoggingAndAuditTrailsForPrivateCACheck
from kite.checks import IacGuardrailsCheck
from kite.checks import IacTemplatesCheck
from kite.checks import IacVersionControlCheck
from kite.checks import IdentityAuditCheck
from kite.checks import ImmutableBuildsCheck
from kite.checks import ImplementAuthAcrossServicesCheck
from kite.checks import ImplementQueryingForLogsCheck
from kite.checks import ImplementRetentionPoliciesCheck
from kite.checks import IncidentResponsePlansCheck
from kite.checks import LessonsLearnedFrameworkCheck
from kite.checks import MacieScansForSensitiveDataCheck
from kite.checks import MaintainInventoryOfSharedResourcesCheck
from kite.checks import MonitorKeyUsageCheck
from kite.checks import MonitorNetworkTrafficForUnauthorizedAccessCheck
from kite.checks import MonitorSecretsCheck
from kite.checks import PenetrationTestingCheck
from kite.checks import PerformDASTCheck
from kite.checks import PerformSASTCheck
from kite.checks import PipelinesUseLeastPrivilegeCheck
from kite.checks import PreDeployToolsCheck
from kite.checks import PreventAndDetectSecretsCheck
from kite.checks import RegularlyReviewPermissionsCheck
from kite.checks import RemediateVulnerabilitiesCheck
from kite.checks import ResolverQueryLogsEnabledCheck
from kite.checks import RootActionsDisallowedCheck
from kite.checks import vulnerability_scanning_in_cicd_pipelines

# Define check themes and their associated checks
CHECK_THEMES: dict[str, dict[str, str | list[Callable | Check]]] = {
    "Multi-Account Architecture": {
        "description": (
            "Checks related to organizational structure, landing zone and guardrails"
        ),
        "checks": [
            check_aws_organizations_usage,
            check_account_separation,
            check_ou_structure,
            check_management_account_workloads,
            check_delegated_admins_security_services,
            check_trusted_delegated_admins,
        ],
    },
    "Root User Security": {
        "description": "Checks related to the security of the root user",
        "checks": [
            check_root_user_usage,
            check_root_credentials_management_enabled,
            check_no_root_access_keys,
            check_root_mfa_enabled,
            check_accurate_account_contact_details,
            check_root_access_keys_disallowed,
            RootActionsDisallowedCheck(),
            check_root_account_monitoring,
            check_root_credentials_security,
            check_root_access_testing,
        ],
    },
    "Control Objective Identification and Validation": {
        "description": (
            "Checks related to the identification and validation of control objectives"
        ),
        "checks": [
            check_well_defined_control_objectives,
            ControlImplementationValidationCheck(),
        ],
    },
    "Threat Intelligence": {
        "description": "Checks related to the use of threat intelligence",
        "checks": [
            check_threat_intelligence_monitoring,
            check_tech_inventories_scanned,
            check_workload_dependency_updates,
            AwsManagedServicesThreatIntelCheck(),
        ],
    },
    "Reducing Security Management Scope": {
        "description": "Checks related to reducing the scope of security management",
        "checks": [
            check_use_of_higher_level_services,
            AwsControlDocumentationCheck(),
            AwsServiceEvaluationCheck(),
        ],
    },
    "Automated Deployment of Standard Security Controls": {
        "description": (
            "Checks related to the automated deployment of standard security controls"
        ),
        "checks": [
            IacTemplatesCheck(),
            IacVersionControlCheck(),
            IacGuardrailsCheck(),
            check_service_catalog,
            AccountStandardsCheck(),
            ControlTowerCheck(),
        ],
    },
    "Threat modeling": {
        "description": (
            "Checks related to threat modeling practices and documentation"
        ),
        "checks": [
            check_threat_modeling,
            DfdsCheck(),
            check_security_risks,
        ],
    },
    "Evaluate and implement new security services": {
        "description": (
            "Checks related to evaluating and implementing new security services"
        ),
        "checks": [
            check_security_services_evaluation,
        ],
    },
    "Use strong sign-in mechanisms": {
        "description": "Checks related to the use of strong sign-in mechanisms",
        "checks": [
            check_require_mfa,
            check_complex_passwords,
        ],
    },
    "Use temporary credentials": {
        "description": "Checks related to the use of temporary credentials",
        "checks": [
            check_no_access_keys,
            check_no_key_pairs,
            check_no_iam_user_access,
        ],
    },
    "Store and use secrets securely": {
        "description": "Checks related to secure storage and use of secrets",
        "checks": [
            check_no_secrets_in_aws_resources,
            PreventAndDetectSecretsCheck(),
            check_secure_secrets_storage,
            MonitorSecretsCheck(),
            check_restricted_role_for_secrets_access,
        ],
    },
    "Rely on a centralized identity provider": {
        "description": "Checks related to using a centralized identity provider",
        "checks": [
            check_use_centralized_idp,
            check_hr_system_integration,
        ],
    },
    "Audit and rotate credentials periodically": {
        "description": (
            "Regularly audit and rotate credentials to maintain security and compliance"
        ),
        "checks": [
            check_credential_rotation,
            IdentityAuditCheck(),
        ],
    },
    "Employ user groups and attributes": {
        "description": (
            "Checks related to using user groups and attributes for permission "
            "management"
        ),
        "checks": [
            EmployUserGroupsAndAttributesCheck(),
        ],
    },
    "Define access requirements": {
        "description": (
            "Checks related to defining and documenting access requirements for "
            "resources and components"
        ),
        "checks": [
            DefineAccessRequirementsCheck(),
        ],
    },
    "Grant least privilege access": {
        "description": (
            "Follow the principle of least privilege by granting only the "
            "permissions required to perform a task."
        ),
        "checks": [
            check_no_full_admin_policies,
            check_no_policy_allows_privilege_escalation,
            check_no_permissive_role_assumption,
            check_no_full_access_to_sensitive_services,
            check_no_readonly_third_party_access,
            check_admin_privileges_are_restricted,
            check_limit_access_to_production_environments,
            check_s3_confused_deputy_protection,
            check_sns_confused_deputy_protection,
            check_sqs_confused_deputy_protection,
            check_lambda_confused_deputy_protection,
            check_kms_confused_deputy_protection,
        ],
    },
    "Establish emergency access procedures": {
        "description": (
            "Checks related to establishing and maintaining emergency access "
            "procedures for critical failure scenarios"
        ),
        "checks": [
            EstablishedEmergencyAccessProceduresCheck(),
        ],
    },
    "Reduce permissions continuously": {
        "description": "Checks related to reducing permissions continuously",
        "checks": [
            check_active_unused_access_analyzer,
            RegularlyReviewPermissionsCheck(),
        ],
    },
    "Define permission guardrails for your organization": {
        "description": (
            "Checks related to defining permission guardrails for your organization"
        ),
        "checks": [
            check_region_deny_scp,
            check_scp_prevents_leaving_org,
            check_scp_prevents_common_admin_role_changes,
            check_scp_prevents_cloudwatch_changes,
            check_scp_prevents_config_changes,
            check_scp_prevents_guardduty_changes,
            check_scp_prevents_unencrypted_s3_uploads,
            check_scp_prevents_deleting_logs,
            check_scp_prevents_adding_internet_access_to_vpc,
            check_delegate_iam_with_permission_boundaries,
        ],
    },
    "Manage access based on lifecycle": {
        "description": ("Checks related to managing access based on lifecycle"),
        "checks": [
            AccessManagementLifecycleCheck(),
            AccessManagementLifecycleImplementedCheck(),
            check_scim_protocol_used,
        ],
    },
    "Analyze public and cross-account access": {
        "description": ("Checks related to analyzing public and cross-account access"),
        "checks": [
            check_active_external_access_analyzer,
            check_monitor_and_response_to_s3_public_access,
            MaintainInventoryOfSharedResourcesCheck(),
            ApprovalProcessForResourceSharingCheck(),
        ],
    },
    "Share resources securely within your organization": {
        "description": (
            "Checks related to sharing resources securely within your organization"
        ),
        "checks": [
            check_scp_prevents_ram_external_sharing,
            check_scp_prevents_ram_invitations,
            check_s3_bucket_acl_disabled,
            check_migrate_from_oai,
            check_establish_data_perimeter_trusted_identities,
            check_data_perimeter_confused_deputy_protection,
            check_data_perimeter_trusted_resources,
            check_vpc_endpoints_enforce_data_perimeter,
            check_data_perimeter_trusted_networks,
        ],
    },
    "Share resources securely with a 3rd party": {
        "description": (
            "Checks related to sharing resources securely with a 3rd party"
        ),
        "checks": [
            check_cross_account_confused_deputy_prevention,
            check_repeatable_auditable_setup_for_3rd_party_access,
        ],
    },
    "Configure service and application logging": {
        "description": (
            "Checks related to configuring service and application logging"
        ),
        "checks": [
            check_organizational_cloudtrail,
            check_vpc_flow_logs_enabled,
            ResolverQueryLogsEnabledCheck(),
            check_log_retention,
            check_waf_web_acl_logging_enabled,
            check_elb_logging_enabled,
            check_eks_control_plane_logging_enabled,
            check_network_firewall_logging_enabled,
            check_rds_logging_enabled,
            check_cloudfront_logging_enabled,
            check_api_gateway_logging_enabled,
            check_config_recording_enabled,
            ImplementQueryingForLogsCheck(),
            check_log_alerting,
        ],
    },
    "Capture logs, findings and metrics in standardized locations": {
        "description": (
            "Checks related to capturing logs, findings and metrics in standardized "
            "locations"
        ),
        "checks": [
            check_security_data_published_to_log_archive_account,
            # TODO: where should we check for log tampering prevention and
            # access control?
            check_deploy_log_analysis_tools_in_audit_account,
        ],
    },
    "Correlate and enrich security alerts": {
        "description": (
            "Checks relating to automated correlation and enrichment of security "
            "alerts to accelerate incident response"
        ),
        "checks": [
            check_detective_enabled,
            check_security_event_correlation,
        ],
    },
    "Initiate remediation for non-compliant resources": {
        "description": (
            "The steps to remedidate when resources are detected to be non-compliant "
            "are defined, programmitically, along with resource configuration "
            "standards so that they can be initiated either manually or "
            "automatically when resources are found to be non-compliant"
        ),
        "checks": [
            check_auto_remediate_non_compliant_resources,
        ],
    },
    "Create network layers": {
        "description": ("Checks related to creating network layers for your workloads"),
        "checks": [
            check_create_network_layers,
        ],
    },
    "Control traffic flow within your network layers": {
        "description": (
            "Checks related to controlling traffic flow within your network layers"
        ),
        "checks": [
            check_control_network_flow_with_nacls,
            check_control_network_flows_with_sgs,
            check_control_network_flows_with_route_tables,
            check_use_private_link_for_vpc_routing,
            check_use_route53resolver_dns_firewall,
        ],
    },
    "Implement inspection-based protection": {
        "description": (
            "Checks related to implementing inspection-based protection for your "
            "workloads"
        ),
        "checks": [
            check_inspect_http_traffic_with_waf,
            check_inspect_traffic_with_network_firewall,
        ],
    },
    "Automate network protection": {
        "description": "",
        "checks": [],
    },
    "Perform vulnerability management": {
        "description": (
            "Checks related to performing vulnerability management for your workloads"
        ),
        "checks": [
            check_scan_workloads_for_vulnerabilities,
            RemediateVulnerabilitiesCheck(),
            check_automate_patch_management,
            vulnerability_scanning_in_cicd_pipelines,
            automate_malware_and_threat_detection,
        ],
    },
    "Provision compute from hardened images": {
        "description": ("Checks related to provisioning compute from hardened images"),
        "checks": [
            check_use_hardened_images,
        ],
    },
    "Reduce manual management and interactive access": {
        "description": (
            "Checks related to reducing manual management and interactive access"
        ),
        "checks": [
            check_no_rdp_or_ssh_access,
            check_avoid_interactive_access,
            check_audit_interactive_access_with_ssm,
        ],
    },
    "Validate software integrity": {
        "description": "Checks related to validating software integrity",
        "checks": [
            check_validate_software_integrity,
        ],
    },
    "Understand your data classification scheme": {
        "description": "Checks relating to the classification of data",
        "checks": [
            DocumentedDataClassificationSchemeCheck(),
            DataCatalogCheck(),
            check_tag_data_with_sensitivity_level,
        ],
    },
    "Apply data protection controls based on data sensitivity": {
        "description": (
            "Checks related to applying data protection controls based on data "
            "sensitivity levels"
        ),
        "checks": [
            check_isolation_boundaries,
            check_controls_implemented_based_on_sensitivity,
            check_tokenization_and_anonymization,
        ],
    },
    "Automate identification and classification": {
        "description": "",
        "checks": [
            check_cw_data_protection_policies,
            check_sns_data_protection_policies,
            check_detect_sensitive_data_transform,
            MacieScansForSensitiveDataCheck(),
            check_scan_for_sensitive_data_in_dev,
        ],
    },
    "Define scalable data lifecycle management": {
        "description": "",
        "checks": [
            check_automate_s3_data_retention,
            check_automate_ddb_data_retention,
            ImplementRetentionPoliciesCheck(),
            check_detect_missing_automated_lifecycle_management,
        ],
    },
    "Implement secure key management": {
        "description": (
            "Checks relating to the storage, rotation, access control, and "
            "monitoring of key material used to secure data at rest for your "
            "workloads."
        ),
        "checks": [
            check_use_a_kms,
            check_no_human_access_to_unencrypted_key_material,
            check_rotate_encryption_keys,
            MonitorKeyUsageCheck(),
            check_key_access_control,
        ],
    },
    "Enforce encryption at rest": {
        "description": (
            "Encrypt private data at rest to maintain confidentiality and provide "
            "an additional layer of protection against unintended data disclosure "
            "or exfiltration"
        ),
        "checks": [
            check_use_service_encryption_at_rest,
            check_use_customer_managed_keys,
        ],
    },
    "Automate data at rest protection": {
        "description": "Use automation to validate and enforce data at rest controls.",
        "checks": [
            check_detect_encryption_at_rest_misconfig,
            EnforceDataProtectionAtRestWithPolicyAsCodeCheck(),
            check_automate_data_at_rest_protection_with_guardduty,
            check_air_gapped_backup_vault,
            check_restore_testing,
        ],
    },
    "Enforce access control": {
        "description": (
            "Checks related to enforcing access control for S3 buckets and "
            "object locking"
        ),
        "checks": [
            check_implement_versioning_and_object_locking,
        ],
    },
    "Implement secure key and certificate management": {
        "description": (
            "Checks relating to the secure management of TLS certificates and their "
            "private keys"
        ),
        "checks": [
            check_cert_deployment_and_renewal,
            check_protect_root_ca,
            EstablishLoggingAndAuditTrailsForPrivateCACheck(),
        ],
    },
    "Enforce encryption in transit": {
        "description": ("Checks related to enforcing encryption in transit"),
        "checks": [
            check_enforce_https,
            check_avoid_insecure_ssl_ciphers,
        ],
    },
    "Authenticate network communications": {
        "description": ("Checks related to authenticating network communications"),
        "checks": [
            DefineAndDocumentWorkloadNetworkFlowsCheck(),
            ImplementAuthAcrossServicesCheck(),
            MonitorNetworkTrafficForUnauthorizedAccessCheck(),
        ],
    },
    "Identify key personnel and external resources": {
        "description": (
            "Checks related to identifying key personnel and external resources"
        ),
        "checks": [
            CaptureKeyContactsCheck(),
        ],
    },
    "Develop incident management plans": {
        "description": "Checks related to developing incident management plans",
        "checks": [
            IncidentResponsePlansCheck(),
        ],
    },
    "Prepare forensic capabilities": {
        "description": "Checks related to preparing forensic capabilities",
        "checks": [
            check_forensics_ou,
            AutomateForensicsCheck(),
        ],
    },
    "Develop and test security incident response playbooks": {
        "description": (
            "Checks related to developing security incident response playbooks"
        ),
        "checks": [
            check_security_ir_playbooks,
        ],
    },
    "Pre-provision access": {
        "description": (
            "Checks related to pre-provisioning access for incident response"
        ),
        "checks": [
            check_use_identity_broker,
        ],
    },
    "Pre-deploy tools": {
        "description": (
            "Checks related to pre-deploying tools required to support "
            "incident response and security operations"
        ),
        "checks": [
            PreDeployToolsCheck(),
        ],
    },
    "Run simulations": {
        "description": (
            "Checks related to running regular simulations to test and "
            "validate incident response capabilities"
        ),
        "checks": [
            check_run_simulations,
        ],
    },
    "Establish a framework for learning from incidents": {
        "description": (
            "Checks related to establishing frameworks and processes for "
            "learning from incidents and applying lessons learned"
        ),
        "checks": [
            LessonsLearnedFrameworkCheck(),
        ],
    },
    "Train for application security": {
        "description": ("Checks related to training for application security"),
        "checks": [
            check_train_for_application_security,
        ],
    },
    "Automate testing throughout the development and release lifecycle": {
        "description": (
            "Checks relating to the automated testing for security properties "
            "throughout the development and release lifecycle"
        ),
        "checks": [
            PerformSASTCheck(),
            PerformDASTCheck(),
            AutomatedSecurityTestsCheck(),
        ],
    },
    "Perform regular penetration testing": {
        "description": "Checks related to performing regular penetration testing",
        "checks": [
            PenetrationTestingCheck(),
        ],
    },
    "Conduct code reviews": {
        "description": (
            "Checks related to conducting code reviews to detect security "
            "vulnerabilities"
        ),
        "checks": [
            CodeReviewsCheck(),
        ],
    },
    "Centralize services for packages and dependencies": {
        "description": (
            "Checks related to using centralized services for packages and dependencies"
        ),
        "checks": [
            CentralizedArtifactReposCheck(),
        ],
    },
    "Deploy software programmatically": {
        "description": "Checks related to deploying software programmatically",
        "checks": [
            AutomateDeploymentsCheck(),
            ImmutableBuildsCheck(),
        ],
    },
    "Regularly assess security properties of the pipelines": {
        "description": (
            "The pipelines you use to build and deploy your software should follow the"
            " same recommended practices as any other workload in your environment"
        ),
        "checks": [
            PipelinesUseLeastPrivilegeCheck(),
            check_review_pipeline_permissions_regularly,
            check_threat_model_pipelines,
        ],
    },
    "Build a program that embeds security ownership in workload teams": {
        "description": (
            "Embed security ownership and decision-making in workload teams"
        ),
        "checks": [
            check_security_guardians_program,
        ],
    },
}

# Flatten all checks for backward compatibility
ALL_CHECKS = [check for theme in CHECK_THEMES.values() for check in theme["checks"]]
