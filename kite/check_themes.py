"""Check themes module for Kite."""

from typing import Callable

from kite.checks import (
    check_aws_organizations_usage,
    check_account_separation,
    check_ou_structure,
    check_management_account_workloads,
    check_delegated_admins_security_services,
    check_trusted_delegated_admins,
    check_region_deny_scp,
    check_root_user_usage,
    check_root_credentials_management_enabled,
    check_no_root_access_keys,
    check_root_mfa_enabled,
    check_accurate_account_contact_details,
    check_root_access_keys_disallowed,
    check_root_actions_disallowed,
    check_root_account_monitoring,
    check_root_credentials_security,
    check_root_access_testing,
    check_well_defined_control_objectives,
    check_control_implementation_validation,
    check_threat_intelligence_monitoring,
    check_tech_inventories_scanned,
    check_workload_dependency_updates,
    check_aws_managed_services_threat_intel,
    check_use_of_higher_level_services,
    check_aws_control_documentation,
    check_aws_service_evaluation,
    check_iac_templates,
    check_iac_version_control,
    check_iac_guardrails,
    check_service_catalog,
    check_account_standards,
    check_control_tower,
    check_threat_modeling,
    check_dfds,
    check_security_risks,
    check_security_services_evaluation,
    check_require_mfa,
    check_complex_passwords,
    check_no_access_keys,
    check_no_key_pairs,
    check_no_iam_user_access,
    check_no_secrets_in_aws_resources,
    check_prevent_and_detect_secrets,
    check_secure_secrets_storage,
    check_monitor_secrets,
    check_restricted_role_for_secrets_access,
    check_use_centralized_idp,
    check_hr_system_integration,
    check_credential_rotation,
    check_identity_audit,
    check_employ_user_groups_and_attributes,
    check_define_access_requirements,
    check_no_full_admin_policies,
    check_no_policy_allows_privilege_escalation,
    check_no_permissive_role_assumption,
    check_no_full_access_to_sensitive_services,
    check_no_readonly_third_party_access,
    check_cross_account_confused_deputy_prevention,
    check_admin_privileges_are_restricted,
    check_limit_access_to_production_environments,
    check_s3_confused_deputy_protection,
    check_sns_confused_deputy_protection,
    check_sqs_confused_deputy_protection,
    check_lambda_confused_deputy_protection,
    check_kms_confused_deputy_protection,
    check_emergency_access_procedures,
    check_active_unused_access_analyzer,
    check_active_external_access_analyzer,
    check_regularly_review_permissions,
    check_scp_prevents_leaving_org,
    check_scp_prevents_common_admin_role_changes,
    check_scp_prevents_cloudwatch_changes,
    check_scp_prevents_config_changes,
    check_scp_prevents_guardduty_changes,
    check_scp_prevents_ram_external_sharing,
    check_scp_prevents_unencrypted_s3_uploads,
    check_scp_prevents_deleting_logs,
    check_scp_prevents_adding_internet_access_to_vpc,
    check_delegate_iam_with_permission_boundaries,
    check_access_management_lifecycle,
    check_access_management_lifecycle_implemented,
    check_scim_protocol_used,
    check_monitor_and_response_to_s3_public_access,
    check_maintain_inventory_of_shared_resources,
    check_approval_process_for_resource_sharing,
    check_s3_bucket_acl_disabled,
    check_migrate_from_oai,
    check_establish_data_perimeter_trusted_identities,
    check_data_perimeter_confused_deputy_protection,
    check_data_perimeter_trusted_resources,
    check_vpc_endpoints_enforce_data_perimeter,
    check_data_perimeter_trusted_networks,
    check_scp_prevents_ram_invitations,
    check_repeatable_auditable_setup_for_3rd_party_access,
    check_organizational_cloudtrail,
    check_vpc_flow_logs_enabled,
    check_resolver_query_logs_enabled,
    check_log_retention,
    check_waf_web_acl_logging_enabled,
    check_elb_logging_enabled,
    check_eks_control_plane_logging_enabled,
    check_network_firewall_logging_enabled,
    check_rds_logging_enabled,
    check_cloudfront_logging_enabled,
    check_api_gateway_logging_enabled,
    check_config_recording_enabled,
    check_log_querying,
    check_log_alerting,
    check_security_data_published_to_log_archive_account,
    check_deploy_log_analysis_tools_in_audit_account,
    check_detective_enabled,
    check_security_event_correlation,
    check_auto_remediate_non_compliant_resources,
    check_documented_data_classification_scheme,
    check_data_catalog,
    check_tag_data_with_sensitivity_level,
    check_isolation_boundaries,
    check_controls_implemented_based_on_sensitivity,
    check_tokenization_and_anonymization,
    check_cw_data_protection_policies,
    check_sns_data_protection_policies,
    check_detect_sensitive_data_transform,
    check_macie_scans_for_sensitive_data,
    check_scan_for_sensitive_data_in_dev,
    check_automate_s3_data_retention,
    check_automate_ddb_data_retention,
    check_implement_retention_policies,
    check_detect_missing_automated_lifecycle_management,
    check_use_a_kms,
    check_no_human_access_to_unencrypted_key_material,
    check_rotate_encryption_keys,
    check_monitor_key_usage,
    check_key_access_control,
    check_use_service_encryption_at_rest,
    check_use_customer_managed_keys,
    check_detect_encryption_at_rest_misconfig,
    check_enforce_data_protection_at_rest_with_policy_as_code,
    check_automate_data_at_rest_protection_with_guardduty,
    check_air_gapped_backup_vault,
    check_restore_testing,
    check_implement_versioning_and_object_locking,
    check_cert_deployment_and_renewal,
    check_protect_root_ca,
    check_establish_logging_and_audit_trails_for_private_ca,
    check_enforce_https,
    check_avoid_insecure_ssl_ciphers,
    check_define_and_document_workload_network_flows,
    check_implement_auth_across_services,
    check_monitor_network_traffic_for_unauthorized_access,
    check_train_for_application_security,
    check_perform_sast,
    check_perform_dast,
    check_automated_security_tests,
    check_perform_regular_pen_testing,
    check_conduct_code_reviews,
    check_use_centralized_artifact_repos,
    check_automate_deployments,
    check_immutable_builds,
    check_pipelines_use_least_privilege,
    check_review_pipeline_permissions_regularly,
    check_threat_model_pipelines,
    check_security_guardians_program,
    check_scan_workloads_for_vulnerabilities,
    check_remediate_vulnerabilities,
    check_automate_patch_management,
    vulnerability_scanning_in_cicd_pipelines,
    automate_malware_and_threat_detection,
    check_use_hardened_images,
    check_no_rdp_or_ssh_access,
    check_avoid_interactive_access,
    check_audit_interactive_access_with_ssm,
    check_validate_software_integrity,
    check_capture_key_contacts,
)

# Define check themes and their associated checks
CHECK_THEMES: dict[str, dict[str, str | list[Callable]]] = {
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
            check_region_deny_scp,
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
            check_root_actions_disallowed,
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
            check_control_implementation_validation,
        ],
    },
    "Threat Intelligence": {
        "description": "Checks related to the use of threat intelligence",
        "checks": [
            check_threat_intelligence_monitoring,
            check_tech_inventories_scanned,
            check_workload_dependency_updates,
            check_aws_managed_services_threat_intel,
        ],
    },
    "Reducing Security Management Scope": {
        "description": "Checks related to reducing the scope of security management",
        "checks": [
            check_use_of_higher_level_services,
            check_aws_control_documentation,
            check_aws_service_evaluation,
        ],
    },
    "Automated Deployment of Standard Security Controls": {
        "description": (
            "Checks related to the automated deployment of standard security controls"
        ),
        "checks": [
            check_iac_templates,
            check_iac_version_control,
            check_iac_guardrails,
            check_service_catalog,
            check_account_standards,
            check_control_tower,
        ],
    },
    "Threat modeling": {
        "description": (
            "Checks related to threat modeling practices and documentation"
        ),
        "checks": [
            check_threat_modeling,
            check_dfds,
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
            check_prevent_and_detect_secrets,
            check_secure_secrets_storage,
            check_monitor_secrets,
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
            check_identity_audit,
        ],
    },
    "Employ user groups and attributes": {
        "description": (
            "Checks related to using user groups and attributes for permission "
            "management"
        ),
        "checks": [
            check_employ_user_groups_and_attributes,
        ],
    },
    "Define access requirements": {
        "description": (
            "Checks related to defining and documenting access requirements for "
            "resources and components"
        ),
        "checks": [
            check_define_access_requirements,
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
            check_emergency_access_procedures,
        ],
    },
    "Reduce permissions continuously": {
        "description": "Checks related to reducing permissions continuously",
        "checks": [
            check_active_unused_access_analyzer,
            check_regularly_review_permissions,
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
            check_scp_prevents_ram_external_sharing,
            check_scp_prevents_unencrypted_s3_uploads,
            check_scp_prevents_deleting_logs,
            check_scp_prevents_adding_internet_access_to_vpc,
            check_delegate_iam_with_permission_boundaries,
        ],
    },
    "Manage access based on lifecycle": {
        "description": ("Checks related to managing access based on lifecycle"),
        "checks": [
            check_access_management_lifecycle,
            check_access_management_lifecycle_implemented,
            check_scim_protocol_used,
        ],
    },
    "Analyze public and cross-account access": {
        "description": ("Checks related to analyzing public and cross-account access"),
        "checks": [
            check_active_external_access_analyzer,
            check_monitor_and_response_to_s3_public_access,
            check_maintain_inventory_of_shared_resources,
            check_approval_process_for_resource_sharing,
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
            check_resolver_query_logs_enabled,
            check_log_retention,
            check_waf_web_acl_logging_enabled,
            check_elb_logging_enabled,
            check_eks_control_plane_logging_enabled,
            check_network_firewall_logging_enabled,
            check_rds_logging_enabled,
            check_cloudfront_logging_enabled,
            check_api_gateway_logging_enabled,
            check_config_recording_enabled,
            check_log_querying,
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
        "description": "",
        "checks": [],
    },
    "Control traffic flow within your network layers": {
        "description": "",
        "checks": [],
    },
    "Implement inspection-based protection": {
        "description": "",
        "checks": [],
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
            check_remediate_vulnerabilities,
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
            check_documented_data_classification_scheme,
            check_data_catalog,
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
            check_macie_scans_for_sensitive_data,
            check_scan_for_sensitive_data_in_dev,
        ],
    },
    "Define scalable data lifecycle management": {
        "description": "",
        "checks": [
            check_automate_s3_data_retention,
            check_automate_ddb_data_retention,
            check_implement_retention_policies,
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
            check_monitor_key_usage,
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
            check_enforce_data_protection_at_rest_with_policy_as_code,
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
            check_establish_logging_and_audit_trails_for_private_ca,
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
            check_define_and_document_workload_network_flows,
            check_implement_auth_across_services,
            check_monitor_network_traffic_for_unauthorized_access,
        ],
    },
    "Identify key personnel and external resources": {
        "description": "Checks related to identifying key personnel and external resources",
        "checks": [
            check_capture_key_contacts,
        ],
    },
    "Develop incident management plans": {
        "description": "",
        "checks": [],
    },
    "Prepare forensic capabilities": {
        "description": "",
        "checks": [],
    },
    "Develop and test security incident response playbooks": {
        "description": "",
        "checks": [],
    },
    "Pre-provision access": {
        "description": "",
        "checks": [],
    },
    "Pre-deploy tools": {
        "description": "",
        "checks": [],
    },
    "Run simulations": {
        "description": "",
        "checks": [],
    },
    "Establish a framework for learning from incidents": {
        "description": "",
        "checks": [],
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
            check_perform_sast,
            check_perform_dast,
            check_automated_security_tests,
        ],
    },
    "Perform regular penetration testing": {
        "description": "Checks related to performing regular penetration testing",
        "checks": [
            check_perform_regular_pen_testing,
        ],
    },
    "Conduct code reviews": {
        "description": (
            "Checks related to conducting code reviews to detect security "
            "vulnerabilities"
        ),
        "checks": [
            check_conduct_code_reviews,
        ],
    },
    "Centralize services for packages and dependencies": {
        "description": (
            "Checks related to using centralized services for packages and dependencies"
        ),
        "checks": [
            check_use_centralized_artifact_repos,
        ],
    },
    "Deploy software programmatically": {
        "description": "Checks related to deploying software programmatically",
        "checks": [
            check_automate_deployments,
            check_immutable_builds,
        ],
    },
    "Regularly assess security properties of the pipelines": {
        "description": (
            "The pipelines you use to build and deploy your software should follow the"
            " same recommended practices as any other workload in your environment"
        ),
        "checks": [
            check_pipelines_use_least_privilege,
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
