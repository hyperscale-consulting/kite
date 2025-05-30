"""Check themes module for Kite."""

from typing import Dict, List, Callable

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
)

# Define check themes and their associated checks
CHECK_THEMES: Dict[str, Dict[str, List[Callable]]] = {
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
            "Checks related to the identification and validation of "
            "control objectives"
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
            "Regularly audit and rotate credentials to maintain security and "
            "compliance"
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
        "description": (
            "Checks related to managing access based on lifecycle"
        ),
        "checks": [
            check_access_management_lifecycle,
            check_access_management_lifecycle_implemented,
            check_scim_protocol_used,
        ],
    },
    "Analyze public and cross-account access": {
        "description": (
            "Checks related to analyzing public and cross-account access"
        ),
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
        ],
    },
}

# Flatten all checks for backward compatibility
ALL_CHECKS = [check for theme in CHECK_THEMES.values() for check in theme["checks"]]
