from kite.checks.access_management_lifecycle import AccessManagementLifecycleCheck
from kite.checks.access_management_lifecycle_implemented import (
    AccessManagementLifecycleImplementedCheck,
)
from kite.checks.account_separation import AccountSeparationCheck
from kite.checks.account_standards import AccountStandardsCheck
from kite.checks.accurate_account_contact_details import (
    AccurateAccountContactDetailsCheck,
)
from kite.checks.active_external_access_analyzer import (
    ActiveExternalAccessAnalyzerCheck,
)
from kite.checks.active_unused_access_analyzer import ActiveUnusedAccessAnalyzerCheck
from kite.checks.admin_privileges_are_restricted import (
    AdminPrivilegesAreRestrictedCheck,
)
from kite.checks.air_gapped_backup_vault import AirGappedBackupVaultCheck
from kite.checks.api_gateway_logging_enabled import ApiGatewayLoggingEnabledCheck
from kite.checks.approval_process_for_resource_sharing import (
    ApprovalProcessForResourceSharingCheck,
)
from kite.checks.audit_interactive_access_with_ssm import (
    AuditInteractiveAccessWithSSMCheck,
)
from kite.checks.auto_remediate_non_compliant_resources import (
    AutoRemediateNonCompliantResourcesCheck,
)
from kite.checks.automate_data_at_rest_protection_with_guardduty import (
    AutomateDataAtRestProtectionWithGuardDutyCheck,
)
from kite.checks.automate_ddb_data_retention import AutomateDdbDataRetentionCheck
from kite.checks.automate_deployments import AutomateDeploymentsCheck
from kite.checks.automate_forensics import AutomateForensicsCheck
from kite.checks.automate_malware_and_threat_detection import (
    AutomateMalwareAndThreatDetectionCheck,
)
from kite.checks.automate_patch_management import AutomatePatchManagementCheck
from kite.checks.automate_s3_data_retention import AutomateS3DataRetentionCheck
from kite.checks.automated_security_tests import AutomatedSecurityTestsCheck
from kite.checks.avoid_insecure_ssl_ciphers import AvoidInsecureSslCiphersCheck
from kite.checks.avoid_interactive_access import AvoidInteractiveAccessCheck
from kite.checks.avoid_root_usage import AvoidRootUsageCheck
from kite.checks.aws_control_documentation import AwsControlDocumentationCheck
from kite.checks.aws_managed_services_threat_intel import (
    AwsManagedServicesThreatIntelCheck,
)
from kite.checks.aws_organizations import AwsOrganizationsUsageCheck
from kite.checks.aws_service_evaluation import AwsServiceEvaluationCheck
from kite.checks.capture_key_contacts import CaptureKeyContactsCheck
from kite.checks.centralized_artifact_repos import CentralizedArtifactReposCheck
from kite.checks.cert_deployment_and_renewal import CertDeploymentAndRenewalCheck
from kite.checks.cloudfront_logging_enabled import CloudfrontLoggingEnabledCheck
from kite.checks.code_reviews import CodeReviewsCheck
from kite.checks.complex_passwords import ComplexPasswordsCheck
from kite.checks.config_recording_enabled import ConfigRecordingEnabledCheck
from kite.checks.control_implementation_validation import (
    ControlImplementationValidationCheck,
)
from kite.checks.control_network_flow_with_nacls import ControlNetworkFlowWithNaclsCheck
from kite.checks.control_network_flows_with_route_tables import (
    ControlNetworkFlowsWithRouteTablesCheck,
)
from kite.checks.control_network_flows_with_sgs import ControlNetworkFlowsWithSGsCheck
from kite.checks.control_tower import ControlTowerCheck
from kite.checks.core import Check
from kite.checks.core import CheckResult
from kite.checks.core import CheckStatus
from kite.checks.core import make_finding
from kite.checks.create_network_layers import CreateNetworkLayersCheck
from kite.checks.credential_rotation import CredentialRotationCheck
from kite.checks.cross_account_confused_deputy_prevention import (
    CrossAccountConfusedDeputyPreventionCheck,
)
from kite.checks.cw_data_protection_policies import CwDataProtectionPoliciesCheck
from kite.checks.data_catalog import DataCatalogCheck
from kite.checks.data_perimeter_confused_deputy_protection import (
    DataPerimeterConfusedDeputyProtectionCheck,
)
from kite.checks.data_perimeter_trusted_identities import (
    check_establish_data_perimeter_trusted_identities,
)
from kite.checks.data_perimeter_trusted_networks import (
    DataPerimeterTrustedNetworksCheck,
)
from kite.checks.data_perimeter_trusted_resources import (
    DataPerimeterTrustedResourcesCheck,
)
from kite.checks.define_access_requirements import DefineAccessRequirementsCheck
from kite.checks.define_and_document_workload_network_flows import (
    DefineAndDocumentWorkloadNetworkFlowsCheck,
)
from kite.checks.delegate_iam_with_permission_boundaries import (
    DelegateIamWithPermissionBoundariesCheck,
)
from kite.checks.delegated_admins import DelegatedAdminForSecurityServices
from kite.checks.deploy_log_analysis_tools_in_audit_account import (
    DeployLogAnalysisToolsInAuditAccountCheck,
)
from kite.checks.detect_encryption_at_rest_misconfig import (
    DetectEncryptionAtRestMisconfigCheck,
)
from kite.checks.detect_missing_automated_lifecycle_management import (
    DetectMissingAutomatedLifecycleManagementCheck,
)
from kite.checks.detect_sensitive_data_transform import (
    DetectSensitiveDataTransformCheck,
)
from kite.checks.detective_enabled import DetectiveEnabledCheck
from kite.checks.dfds import DfdsCheck
from kite.checks.documented_data_classification_scheme import (
    DocumentedDataClassificationSchemeCheck,
)
from kite.checks.eks_control_plane_logging_enabled import (
    EksControlPlaneLoggingEnabledCheck,
)
from kite.checks.elb_logging_enabled import ElbLoggingEnabledCheck
from kite.checks.employ_user_groups_and_attributes import (
    EmployUserGroupsAndAttributesCheck,
)
from kite.checks.enforce_data_protection_at_rest_with_policy_as_code import (
    EnforceDataProtectionAtRestWithPolicyAsCodeCheck,
)
from kite.checks.enforce_https import EnforceHttpsCheck
from kite.checks.establish_logging_and_audit_trails_for_private_ca import (
    EstablishLoggingAndAuditTrailsForPrivateCACheck,
)
from kite.checks.established_emergency_access_procedures import (
    EstablishedEmergencyAccessProceduresCheck,
)
from kite.checks.forensics_ou import ForensicsOuCheck
from kite.checks.hr_system_integration import HrSystemIntegrationCheck
from kite.checks.iac_guardrails import IacGuardrailsCheck
from kite.checks.iac_templates import IacTemplatesCheck
from kite.checks.iac_version_control import IacVersionControlCheck
from kite.checks.identity_audit import IdentityAuditCheck
from kite.checks.immutable_builds import ImmutableBuildsCheck
from kite.checks.implement_auth_across_services import ImplementAuthAcrossServicesCheck
from kite.checks.implement_querying_for_logs import ImplementQueryingForLogsCheck
from kite.checks.implement_retention_policies import ImplementRetentionPoliciesCheck
from kite.checks.implement_versioning_and_object_locking import (
    ImplementVersioningAndObjectLockingCheck,
)
from kite.checks.incident_response_plans import IncidentResponsePlansCheck
from kite.checks.inspect_http_traffic_with_waf import InspectHttpTrafficWithWafCheck
from kite.checks.inspect_traffic_with_network_firewall import (
    InspectTrafficWithNetworkFirewallCheck,
)
from kite.checks.isolation_boundaries import IsolationBoundariesCheck
from kite.checks.key_access_control import KeyAccessControlCheck
from kite.checks.kms_confused_deputy_protection import KmsConfusedDeputyProtectionCheck
from kite.checks.lambda_confused_deputy_protection import (
    LambdaConfusedDeputyProtectionCheck,
)
from kite.checks.lessons_learned_framework import LessonsLearnedFrameworkCheck
from kite.checks.limit_access_to_production_environments import (
    LimitAccessToProductionEnvironmentsCheck,
)
from kite.checks.log_retention import LogRetentionCheck
from kite.checks.macie_scans_for_sensitive_data import MacieScansForSensitiveDataCheck
from kite.checks.maintain_inventory_of_shared_resources import (
    MaintainInventoryOfSharedResourcesCheck,
)
from kite.checks.management_account_workloads import check_management_account_workloads
from kite.checks.migrate_from_oai import check_migrate_from_oai
from kite.checks.monitor_and_response_to_s3_public_access import (
    check_monitor_and_response_to_s3_public_access,
)
from kite.checks.monitor_key_usage import MonitorKeyUsageCheck
from kite.checks.monitor_network_traffic_for_unauthorized_access import (
    MonitorNetworkTrafficForUnauthorizedAccessCheck,
)
from kite.checks.monitor_secrets import MonitorSecretsCheck
from kite.checks.network_firewall_logging_enabled import (
    check_network_firewall_logging_enabled,
)
from kite.checks.no_access_keys import check_no_access_keys
from kite.checks.no_full_access_to_sensitive_services import (
    check_no_full_access_to_sensitive_services,
)
from kite.checks.no_full_admin_policies import NoFullAdminPoliciesCheck
from kite.checks.no_human_access_to_unencrypted_key_material import (
    check_no_human_access_to_unencrypted_key_material,
)
from kite.checks.no_iam_user_access import NoIamUserAccessCheck
from kite.checks.no_key_pairs import check_no_key_pairs
from kite.checks.no_permissive_role_assumption import (
    check_no_permissive_role_assumption,
)
from kite.checks.no_policy_allows_privilege_escalation import (
    check_no_policy_allows_privilege_escalation,
)
from kite.checks.no_rdp_or_ssh_access import check_no_rdp_or_ssh_access
from kite.checks.no_readonly_third_party_access import NoReadonlyThirdPartyAccessCheck
from kite.checks.no_root_access_keys import check_no_root_access_keys
from kite.checks.no_secrets_in_aws_resources import check_no_secrets_in_aws_resources
from kite.checks.organizational_cloudtrail import check_organizational_cloudtrail
from kite.checks.ou_structure import check_ou_structure
from kite.checks.penetration_testing import PenetrationTestingCheck
from kite.checks.perform_dast import PerformDASTCheck
from kite.checks.perform_sast import PerformSASTCheck
from kite.checks.pipelines_use_least_privilege import PipelinesUseLeastPrivilegeCheck
from kite.checks.pre_deploy_tools import PreDeployToolsCheck
from kite.checks.prevent_and_detect_secrets import PreventAndDetectSecretsCheck
from kite.checks.protect_root_ca import check_protect_root_ca
from kite.checks.rds_logging_enabled import check_rds_logging_enabled
from kite.checks.region_deny_scp import check_region_deny_scp
from kite.checks.regularly_review_permissions import RegularlyReviewPermissionsCheck
from kite.checks.remediate_vulnerabilities import RemediateVulnerabilitiesCheck
from kite.checks.repeatable_auditable_setup_for_3rd_party_access import (
    RepeatableAuditableSetupFor3rdPartyAccessCheck,
)
from kite.checks.require_mfa import RequireMfaCheck
from kite.checks.resolver_query_logs_enabled import ResolverQueryLogsEnabledCheck
from kite.checks.restore_testing import RestoreTestingCheck
from kite.checks.restricted_role_for_secrets_access import (
    RestrictedRoleForSecretsAccessCheck,
)
from kite.checks.review_pipeline_permissions_regularly import (
    ReviewPipelinePermissionsRegularlyCheck,
)
from kite.checks.root_access_keys_disallowed import RootAccessKeysDisallowedCheck
from kite.checks.root_access_testing import RootAccessTestingCheck
from kite.checks.root_account_monitoring import RootAccountMonitoringCheck
from kite.checks.root_actions_disallowed import RootActionsDisallowedCheck
from kite.checks.root_credentials_management_enabled import (
    check_root_credentials_management_enabled,
)
from kite.checks.root_credentials_security import RootCredentialsSecurityCheck
from kite.checks.root_mfa_enabled import check_root_mfa_enabled
from kite.checks.rotate_encryption_keys import check_rotate_encryption_keys
from kite.checks.run_simulations import RunSimulationsCheck
from kite.checks.s3_bucket_acl_disabled import check_s3_bucket_acl_disabled
from kite.checks.s3_confused_deputy_protection import S3ConfusedDeputyProtectionCheck
from kite.checks.scan_for_sensitive_data_in_dev import ScanForSensitiveDataInDevCheck
from kite.checks.scan_workloads_for_vulnerabilities import (
    check_scan_workloads_for_vulnerabilities,
)
from kite.checks.scim_protocol_used import check_scim_protocol_used
from kite.checks.scp_prevents_adding_internet_access_to_vpc import (
    check_scp_prevents_adding_internet_access_to_vpc,
)
from kite.checks.scp_prevents_cloudwatch_changes import (
    check_scp_prevents_cloudwatch_changes,
)
from kite.checks.scp_prevents_common_admin_role_changes import (
    check_scp_prevents_common_admin_role_changes,
)
from kite.checks.scp_prevents_config_changes import check_scp_prevents_config_changes
from kite.checks.scp_prevents_deleting_logs import check_scp_prevents_deleting_logs
from kite.checks.scp_prevents_guardduty_changes import (
    check_scp_prevents_guardduty_changes,
)
from kite.checks.scp_prevents_leaving_org import ScpPreventsLeavingOrgCheck
from kite.checks.scp_prevents_ram_external_sharing import (
    check_scp_prevents_ram_external_sharing,
)
from kite.checks.scp_prevents_ram_invitations import check_scp_prevents_ram_invitations
from kite.checks.scp_prevents_unencrypted_s3_uploads import (
    check_scp_prevents_unencrypted_s3_uploads,
)
from kite.checks.secure_secrets_storage import SecureSecretsStorageCheck
from kite.checks.security_data_published_to_log_archive_account import (
    SecurityDataPublishedToLogArchiveAccountCheck,
)
from kite.checks.security_event_correlation import SecurityEventCorrelationCheck
from kite.checks.security_guardians_program import SecurityGuardiansProgramCheck
from kite.checks.security_ir_playbooks import SecurityIrPlaybooksCheck
from kite.checks.security_risks import SecurityRisksCheck
from kite.checks.security_services_evaluation import check_security_services_evaluation
from kite.checks.sensitivity_controls import SensitivityControlsCheck
from kite.checks.service_catalog import ServiceCatalogCheck
from kite.checks.sns_confused_deputy_protection import SnsConfusedDeputyProtectionCheck
from kite.checks.sns_data_protection_policies import SnsDataProtectionPoliciesCheck
from kite.checks.sqs_confused_deputy_protection import SqsConfusedDeputyProtectionCheck
from kite.checks.tag_data_with_sensitivity_level import (
    check_tag_data_with_sensitivity_level,
)
from kite.checks.tech_inventories_scanned import TechInventoriesScannedCheck
from kite.checks.threat_intelligence_monitoring import ThreatIntelligenceMonitoringCheck
from kite.checks.threat_model_pipelines import ThreatModelPipelinesCheck
from kite.checks.threat_modeling import ThreatModelingCheck
from kite.checks.tokenization_and_anonymization import TokenizationAndAnonymizationCheck
from kite.checks.train_for_application_security import TrainForApplicationSecurityCheck
from kite.checks.trusted_delegated_admins import TrustedDelegatedAdminsCheck
from kite.checks.use_a_kms import check_use_a_kms
from kite.checks.use_centralized_idp import check_use_centralized_idp
from kite.checks.use_customer_managed_keys import check_use_customer_managed_keys
from kite.checks.use_hardened_images import UseHardenedImagesCheck
from kite.checks.use_identity_broker import UseIdentityBrokerCheck
from kite.checks.use_logs_for_alerting import check_log_alerting
from kite.checks.use_of_higher_level_services import UseOfHigherLevelServicesCheck
from kite.checks.use_private_link_for_vpc_routing import (
    UsePrivateLinkForVpcRoutingCheck,
)
from kite.checks.use_route53resolver_dns_firewall import (
    UseRoute53ResolverDnsFirewallCheck,
)
from kite.checks.use_service_encryption_at_rest import (
    check_use_service_encryption_at_rest,
)
from kite.checks.validate_software_integrity import ValidateSoftwareIntegrityCheck
from kite.checks.vpc_endpoints_enforce_data_perimeter import (
    check_vpc_endpoints_enforce_data_perimeter,
)
from kite.checks.vpc_flow_logs_enabled import check_vpc_flow_logs_enabled
from kite.checks.vulnerability_scanning_in_cicd_pipelines import (
    VulnerabilityScanningInCICDPipelinesCheck,
)
from kite.checks.waf_web_acl_logging_enabled import check_waf_web_acl_logging_enabled
from kite.checks.well_defined_control_objectives import (
    WellDefinedControlObjectivesCheck,
)
from kite.checks.workload_dependency_updates import WorkloadDependencyUpdatesCheck

__all__ = [
    "AwsOrganizationsUsageCheck",
    "AccountSeparationCheck",
    "check_ou_structure",
    "check_management_account_workloads",
    "DelegatedAdminForSecurityServices",
    "TrustedDelegatedAdminsCheck",
    "check_region_deny_scp",
    "check_root_mfa_enabled",
    "RootAccessKeysDisallowedCheck",
    "RootActionsDisallowedCheck",
    "UseOfHigherLevelServicesCheck",
    "IacTemplatesCheck",
    "IacVersionControlCheck",
    "IacGuardrailsCheck",
    "ServiceCatalogCheck",
    "check_no_key_pairs",
    "check_no_secrets_in_aws_resources",
    "AvoidRootUsageCheck",
    "check_root_credentials_management_enabled",
    "check_no_root_access_keys",
    "AccurateAccountContactDetailsCheck",
    "RootAccountMonitoringCheck",
    "RootCredentialsSecurityCheck",
    "RootAccessTestingCheck",
    "WellDefinedControlObjectivesCheck",
    "ThreatIntelligenceMonitoringCheck",
    "TechInventoriesScannedCheck",
    "WorkloadDependencyUpdatesCheck",
    "ThreatModelingCheck",
    "SecurityRisksCheck",
    "check_security_services_evaluation",
    "RequireMfaCheck",
    "ComplexPasswordsCheck",
    "check_no_access_keys",
    "NoIamUserAccessCheck",
    "SecureSecretsStorageCheck",
    "RestrictedRoleForSecretsAccessCheck",
    "check_use_centralized_idp",
    "HrSystemIntegrationCheck",
    "CredentialRotationCheck",
    "IdentityAuditCheck",
    "EmployUserGroupsAndAttributesCheck",
    "NoFullAdminPoliciesCheck",
    "check_no_policy_allows_privilege_escalation",
    "check_no_permissive_role_assumption",
    "check_no_full_access_to_sensitive_services",
    "NoReadonlyThirdPartyAccessCheck",
    "CrossAccountConfusedDeputyPreventionCheck",
    "AdminPrivilegesAreRestrictedCheck",
    "LimitAccessToProductionEnvironmentsCheck",
    "S3ConfusedDeputyProtectionCheck",
    "SnsConfusedDeputyProtectionCheck",
    "SqsConfusedDeputyProtectionCheck",
    "LambdaConfusedDeputyProtectionCheck",
    "EstablishedEmergencyAccessProceduresCheck",
    "ActiveUnusedAccessAnalyzerCheck",
    "ScpPreventsLeavingOrgCheck",
    "check_scp_prevents_common_admin_role_changes",
    "check_scp_prevents_cloudwatch_changes",
    "check_scp_prevents_config_changes",
    "check_scp_prevents_guardduty_changes",
    "check_scp_prevents_ram_external_sharing",
    "check_scp_prevents_unencrypted_s3_uploads",
    "check_scp_prevents_deleting_logs",
    "check_scp_prevents_adding_internet_access_to_vpc",
    "DelegateIamWithPermissionBoundariesCheck",
    "AccessManagementLifecycleCheck",
    "AccessManagementLifecycleImplementedCheck",
    "check_scim_protocol_used",
    "ActiveExternalAccessAnalyzerCheck",
    "check_monitor_and_response_to_s3_public_access",
    "check_s3_bucket_acl_disabled",
    "check_migrate_from_oai",
    "check_establish_data_perimeter_trusted_identities",
    "DataPerimeterConfusedDeputyProtectionCheck",
    "DataPerimeterTrustedResourcesCheck",
    "check_vpc_endpoints_enforce_data_perimeter",
    "check_scp_prevents_ram_invitations",
    "KmsConfusedDeputyProtectionCheck",
    "RepeatableAuditableSetupFor3rdPartyAccessCheck",
    "check_organizational_cloudtrail",
    "check_vpc_flow_logs_enabled",
    "ResolverQueryLogsEnabledCheck",
    "LogRetentionCheck",
    "check_waf_web_acl_logging_enabled",
    "ElbLoggingEnabledCheck",
    "EksControlPlaneLoggingEnabledCheck",
    "check_network_firewall_logging_enabled",
    "check_rds_logging_enabled",
    "CloudfrontLoggingEnabledCheck",
    "ApiGatewayLoggingEnabledCheck",
    "ConfigRecordingEnabledCheck",
    "check_log_alerting",
    "SecurityDataPublishedToLogArchiveAccountCheck",
    "DeployLogAnalysisToolsInAuditAccountCheck",
    "SecurityEventCorrelationCheck",
    "AutoRemediateNonCompliantResourcesCheck",
    "check_tag_data_with_sensitivity_level",
    "IsolationBoundariesCheck",
    "SensitivityControlsCheck",
    "TokenizationAndAnonymizationCheck",
    "SnsDataProtectionPoliciesCheck",
    "CwDataProtectionPoliciesCheck",
    "DetectSensitiveDataTransformCheck",
    "ScanForSensitiveDataInDevCheck",
    "AutomateS3DataRetentionCheck",
    "AutomateDdbDataRetentionCheck",
    "DetectMissingAutomatedLifecycleManagementCheck",
    "check_use_a_kms",
    "check_no_human_access_to_unencrypted_key_material",
    "check_rotate_encryption_keys",
    "KeyAccessControlCheck",
    "check_use_service_encryption_at_rest",
    "check_use_customer_managed_keys",
    "DetectEncryptionAtRestMisconfigCheck",
    "EnforceDataProtectionAtRestWithPolicyAsCodeCheck",
    "EstablishLoggingAndAuditTrailsForPrivateCACheck",
    "AutomateDataAtRestProtectionWithGuardDutyCheck",
    "RestoreTestingCheck",
    "ImplementVersioningAndObjectLockingCheck",
    "check_protect_root_ca",
    "EnforceHttpsCheck",
    "AvoidInsecureSslCiphersCheck",
    "TrainForApplicationSecurityCheck",
    "ImmutableBuildsCheck",
    "ImplementAuthAcrossServicesCheck",
    "ImplementQueryingForLogsCheck",
    "ImplementRetentionPoliciesCheck",
    "IncidentResponsePlansCheck",
    "LessonsLearnedFrameworkCheck",
    "MacieScansForSensitiveDataCheck",
    "MaintainInventoryOfSharedResourcesCheck",
    "MonitorKeyUsageCheck",
    "MonitorNetworkTrafficForUnauthorizedAccessCheck",
    "MonitorSecretsCheck",
    "PenetrationTestingCheck",
    "PerformDASTCheck",
    "PerformSASTCheck",
    "PipelinesUseLeastPrivilegeCheck",
    "PreDeployToolsCheck",
    "PreventAndDetectSecretsCheck",
    "RegularlyReviewPermissionsCheck",
    "RemediateVulnerabilitiesCheck",
    "ReviewPipelinePermissionsRegularlyCheck",
    "ThreatModelPipelinesCheck",
    "SecurityGuardiansProgramCheck",
    "check_scan_workloads_for_vulnerabilities",
    "VulnerabilityScanningInCICDPipelinesCheck",
    "AutomateMalwareAndThreatDetectionCheck",
    "UseHardenedImagesCheck",
    "check_no_rdp_or_ssh_access",
    "AvoidInteractiveAccessCheck",
    "AuditInteractiveAccessWithSSMCheck",
    "ValidateSoftwareIntegrityCheck",
    "ForensicsOuCheck",
    "SecurityIrPlaybooksCheck",
    "UseIdentityBrokerCheck",
    "RunSimulationsCheck",
    "CreateNetworkLayersCheck",
    "ControlNetworkFlowWithNaclsCheck",
    "UsePrivateLinkForVpcRoutingCheck",
    "UseRoute53ResolverDnsFirewallCheck",
    "InspectHttpTrafficWithWafCheck",
    "InspectTrafficWithNetworkFirewallCheck",
    "Check",
    "CheckResult",
    "CheckStatus",
    "make_finding",
    "CaptureKeyContactsCheck",
    "AccountStandardsCheck",
    "ApprovalProcessForResourceSharingCheck",
    "AutomateDeploymentsCheck",
    "AutomateForensicsCheck",
    "AutomatedSecurityTestsCheck",
    "AwsControlDocumentationCheck",
    "AwsManagedServicesThreatIntelCheck",
    "AwsServiceEvaluationCheck",
    "CentralizedArtifactReposCheck",
    "CodeReviewsCheck",
    "ControlImplementationValidationCheck",
    "ControlTowerCheck",
    "DataCatalogCheck",
    "DefineAccessRequirementsCheck",
    "DefineAndDocumentWorkloadNetworkFlowsCheck",
    "DfdsCheck",
    "DocumentedDataClassificationSchemeCheck",
    "DetectiveEnabledCheck",
    "ControlNetworkFlowsWithSGsCheck",
    "ControlNetworkFlowsWithRouteTablesCheck",
    "AutomatePatchManagementCheck",
    "AirGappedBackupVaultCheck",
    "CertDeploymentAndRenewalCheck",
    "DataPerimeterTrustedNetworksCheck",
]
