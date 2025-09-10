from dataclasses import dataclass

from hyperscale.kite.checks.access_management_lifecycle import (
    AccessManagementLifecycleCheck,
)
from hyperscale.kite.checks.access_management_lifecycle_implemented import (
    AccessManagementLifecycleImplementedCheck,
)
from hyperscale.kite.checks.account_separation import AccountSeparationCheck
from hyperscale.kite.checks.accurate_account_contact_details import (
    AccurateAccountContactDetailsCheck,
)
from hyperscale.kite.checks.active_external_access_analyzer import (
    ActiveExternalAccessAnalyzerCheck,
)
from hyperscale.kite.checks.active_unused_access_analyzer import (
    ActiveUnusedAccessAnalyzerCheck,
)
from hyperscale.kite.checks.admin_privileges_are_restricted import (
    AdminPrivilegesAreRestrictedCheck,
)
from hyperscale.kite.checks.air_gapped_backup_vault import AirGappedBackupVaultCheck
from hyperscale.kite.checks.api_gateway_logging_enabled import (
    ApiGatewayLoggingEnabledCheck,
)
from hyperscale.kite.checks.approval_process_for_resource_sharing import (
    ApprovalProcessForResourceSharingCheck,
)
from hyperscale.kite.checks.audit_interactive_access_with_ssm import (
    AuditInteractiveAccessWithSSMCheck,
)
from hyperscale.kite.checks.auto_remediate_non_compliant_resources import (
    AutoRemediateNonCompliantResourcesCheck,
)
from hyperscale.kite.checks.automate_data_at_rest_protection_with_guardduty import (
    AutomateDataAtRestProtectionWithGuardDutyCheck,
)
from hyperscale.kite.checks.automate_ddb_data_retention import (
    AutomateDdbDataRetentionCheck,
)
from hyperscale.kite.checks.automate_deployments import AutomateDeploymentsCheck
from hyperscale.kite.checks.automate_forensics import AutomateForensicsCheck
from hyperscale.kite.checks.automate_malware_and_threat_detection import (
    AutomateMalwareAndThreatDetectionCheck,
)
from hyperscale.kite.checks.automate_patch_management import (
    AutomatePatchManagementCheck,
)
from hyperscale.kite.checks.automate_s3_data_retention import (
    AutomateS3DataRetentionCheck,
)
from hyperscale.kite.checks.automated_security_tests import AutomatedSecurityTestsCheck
from hyperscale.kite.checks.avoid_insecure_ssl_ciphers import (
    AvoidInsecureSslCiphersCheck,
)
from hyperscale.kite.checks.avoid_interactive_access import AvoidInteractiveAccessCheck
from hyperscale.kite.checks.avoid_root_usage import AvoidRootUsageCheck
from hyperscale.kite.checks.aws_control_documentation import (
    AwsControlDocumentationCheck,
)
from hyperscale.kite.checks.aws_managed_services_threat_intel import (
    AwsManagedServicesThreatIntelCheck,
)
from hyperscale.kite.checks.aws_organizations import AwsOrganizationsUsageCheck
from hyperscale.kite.checks.aws_service_evaluation import AwsServiceEvaluationCheck
from hyperscale.kite.checks.capture_key_contacts import CaptureKeyContactsCheck
from hyperscale.kite.checks.centralized_artifact_repos import (
    CentralizedArtifactReposCheck,
)
from hyperscale.kite.checks.cert_deployment_and_renewal import (
    CertDeploymentAndRenewalCheck,
)
from hyperscale.kite.checks.cloudfront_logging_enabled import (
    CloudfrontLoggingEnabledCheck,
)
from hyperscale.kite.checks.code_reviews import CodeReviewsCheck
from hyperscale.kite.checks.complex_passwords import ComplexPasswordsCheck
from hyperscale.kite.checks.config_recording_enabled import ConfigRecordingEnabledCheck
from hyperscale.kite.checks.control_implementation_validation import (
    ControlImplementationValidationCheck,
)
from hyperscale.kite.checks.control_network_flow_with_nacls import (
    ControlNetworkFlowWithNaclsCheck,
)
from hyperscale.kite.checks.control_network_flows_with_route_tables import (
    ControlNetworkFlowsWithRouteTablesCheck,
)
from hyperscale.kite.checks.control_network_flows_with_sgs import (
    ControlNetworkFlowsWithSGsCheck,
)
from hyperscale.kite.checks.core import Check
from hyperscale.kite.checks.core import CheckResult
from hyperscale.kite.checks.core import CheckStatus
from hyperscale.kite.checks.create_network_layers import CreateNetworkLayersCheck
from hyperscale.kite.checks.credential_rotation import CredentialRotationCheck
from hyperscale.kite.checks.cross_account_confused_deputy_prevention import (
    CrossAccountConfusedDeputyPreventionCheck,
)
from hyperscale.kite.checks.cw_data_protection_policies import (
    CwDataProtectionPoliciesCheck,
)
from hyperscale.kite.checks.data_catalog import DataCatalogCheck
from hyperscale.kite.checks.data_perimeter_confused_deputy_protection import (
    DataPerimeterConfusedDeputyProtectionCheck,
)
from hyperscale.kite.checks.data_perimeter_trusted_identities import (
    DataPerimeterTrustedIdentitiesCheck,
)
from hyperscale.kite.checks.data_perimeter_trusted_networks import (
    DataPerimeterTrustedNetworksCheck,
)
from hyperscale.kite.checks.data_perimeter_trusted_resources import (
    DataPerimeterTrustedResourcesCheck,
)
from hyperscale.kite.checks.define_access_requirements import (
    DefineAccessRequirementsCheck,
)
from hyperscale.kite.checks.define_and_document_workload_network_flows import (
    DefineAndDocumentWorkloadNetworkFlowsCheck,
)
from hyperscale.kite.checks.delegate_iam_with_permission_boundaries import (
    DelegateIamWithPermissionBoundariesCheck,
)
from hyperscale.kite.checks.delegated_admins import DelegatedAdminForSecurityServices
from hyperscale.kite.checks.deploy_log_analysis_tools_in_audit_account import (
    DeployLogAnalysisToolsInAuditAccountCheck,
)
from hyperscale.kite.checks.detect_encryption_at_rest_misconfig import (
    DetectEncryptionAtRestMisconfigCheck,
)
from hyperscale.kite.checks.detect_missing_automated_lifecycle_management import (
    DetectMissingAutomatedLifecycleManagementCheck,
)
from hyperscale.kite.checks.detect_sensitive_data_transform import (
    DetectSensitiveDataTransformCheck,
)
from hyperscale.kite.checks.detective_enabled import DetectiveEnabledCheck
from hyperscale.kite.checks.documented_data_classification_scheme import (
    DocumentedDataClassificationSchemeCheck,
)
from hyperscale.kite.checks.eks_control_plane_logging_enabled import (
    EksControlPlaneLoggingEnabledCheck,
)
from hyperscale.kite.checks.elb_logging_enabled import ElbLoggingEnabledCheck
from hyperscale.kite.checks.employ_user_groups_and_attributes import (
    EmployUserGroupsAndAttributesCheck,
)
from hyperscale.kite.checks.enforce_data_protection_at_rest_with_policy_as_code import (
    EnforceDataProtectionAtRestWithPolicyAsCodeCheck,
)
from hyperscale.kite.checks.enforce_https import EnforceHttpsCheck
from hyperscale.kite.checks.establish_logging_and_audit_trails_for_private_ca import (
    EstablishLoggingAndAuditTrailsForPrivateCACheck,
)
from hyperscale.kite.checks.established_emergency_access_procedures import (
    EstablishedEmergencyAccessProceduresCheck,
)
from hyperscale.kite.checks.forensics_ou import ForensicsOuCheck
from hyperscale.kite.checks.hr_system_integration import HrSystemIntegrationCheck
from hyperscale.kite.checks.iac_guardrails import IacGuardrailsCheck
from hyperscale.kite.checks.iac_templates import IacTemplatesCheck
from hyperscale.kite.checks.iac_version_control import IacVersionControlCheck
from hyperscale.kite.checks.identity_audit import IdentityAuditCheck
from hyperscale.kite.checks.immutable_builds import ImmutableBuildsCheck
from hyperscale.kite.checks.implement_auth_across_services import (
    ImplementAuthAcrossServicesCheck,
)
from hyperscale.kite.checks.implement_querying_for_logs import (
    ImplementQueryingForLogsCheck,
)
from hyperscale.kite.checks.implement_retention_policies import (
    ImplementRetentionPoliciesCheck,
)
from hyperscale.kite.checks.implement_versioning_and_object_locking import (
    ImplementVersioningAndObjectLockingCheck,
)
from hyperscale.kite.checks.incident_response_plans import IncidentResponsePlansCheck
from hyperscale.kite.checks.inspect_http_traffic_with_waf import (
    InspectHttpTrafficWithWafCheck,
)
from hyperscale.kite.checks.inspect_traffic_with_network_firewall import (
    InspectTrafficWithNetworkFirewallCheck,
)
from hyperscale.kite.checks.isolation_boundaries import IsolationBoundariesCheck
from hyperscale.kite.checks.key_access_control import KeyAccessControlCheck
from hyperscale.kite.checks.kms_confused_deputy_protection import (
    KmsConfusedDeputyProtectionCheck,
)
from hyperscale.kite.checks.lambda_confused_deputy_protection import (
    LambdaConfusedDeputyProtectionCheck,
)
from hyperscale.kite.checks.lessons_learned_framework import (
    LessonsLearnedFrameworkCheck,
)
from hyperscale.kite.checks.limit_access_to_production_environments import (
    LimitAccessToProductionEnvironmentsCheck,
)
from hyperscale.kite.checks.log_retention import LogRetentionCheck
from hyperscale.kite.checks.macie_scans_for_sensitive_data import (
    MacieScansForSensitiveDataCheck,
)
from hyperscale.kite.checks.maintain_inventory_of_shared_resources import (
    MaintainInventoryOfSharedResourcesCheck,
)
from hyperscale.kite.checks.management_account_workloads import (
    ManagementAccountWorkloadsCheck,
)
from hyperscale.kite.checks.migrate_from_oai import MigrateFromOaiCheck
from hyperscale.kite.checks.monitor_and_respond_to_s3_public_access import (
    MonitorAndRespondToS3PublicAccessCheck,
)
from hyperscale.kite.checks.monitor_key_usage import MonitorKeyUsageCheck
from hyperscale.kite.checks.monitor_network_traffic_for_unauthorized_access import (
    MonitorNetworkTrafficForUnauthorizedAccessCheck,
)
from hyperscale.kite.checks.monitor_secrets import MonitorSecretsCheck
from hyperscale.kite.checks.network_firewall_logging_enabled import (
    NetworkFirewallLoggingEnabledCheck,
)
from hyperscale.kite.checks.no_access_keys import NoAccessKeysCheck
from hyperscale.kite.checks.no_full_access_to_sensitive_services import (
    NoFullAccessToSensitiveServicesCheck,
)
from hyperscale.kite.checks.no_full_admin_policies import NoFullAdminPoliciesCheck
from hyperscale.kite.checks.no_human_access_to_unencrypted_key_material import (
    NoHumanAccessToUnencryptedKeyMaterialCheck,
)
from hyperscale.kite.checks.no_iam_user_access import NoIamUserAccessCheck
from hyperscale.kite.checks.no_key_pairs import NoKeyPairsCheck
from hyperscale.kite.checks.no_permissive_role_assumption import (
    NoPermissiveRoleAssumptionCheck,
)
from hyperscale.kite.checks.no_policy_allows_privilege_escalation import (
    NoPolicyAllowsPrivilegeEscalationCheck,
)
from hyperscale.kite.checks.no_rdp_or_ssh_access import NoRdpOrSshAccessCheck
from hyperscale.kite.checks.no_readonly_third_party_access import (
    NoReadonlyThirdPartyAccessCheck,
)
from hyperscale.kite.checks.no_root_access_keys import NoRootAccessKeysCheck
from hyperscale.kite.checks.no_secrets_in_aws_resources import (
    NoSecretsInAwsResourcesCheck,
)
from hyperscale.kite.checks.organizational_cloudtrail import (
    OrganizationalCloudTrailCheck,
)
from hyperscale.kite.checks.ou_structure import OuStructureCheck
from hyperscale.kite.checks.penetration_testing import PenetrationTestingCheck
from hyperscale.kite.checks.perform_dast import PerformDASTCheck
from hyperscale.kite.checks.perform_sast import PerformSASTCheck
from hyperscale.kite.checks.pipelines_use_least_privilege import (
    PipelinesUseLeastPrivilegeCheck,
)
from hyperscale.kite.checks.pre_deploy_tools import PreDeployToolsCheck
from hyperscale.kite.checks.prevent_and_detect_secrets import (
    PreventAndDetectSecretsCheck,
)
from hyperscale.kite.checks.protect_root_ca import ProtectRootCaCheck
from hyperscale.kite.checks.provide_secure_configs import (
    ProvideSecureConfigurationsCheck,
)
from hyperscale.kite.checks.rds_logging_enabled import RdsLoggingEnabledCheck
from hyperscale.kite.checks.region_deny_scp import RegionDenyScpCheck
from hyperscale.kite.checks.regularly_review_permissions import (
    RegularlyReviewPermissionsCheck,
)
from hyperscale.kite.checks.remediate_vulnerabilities import (
    RemediateVulnerabilitiesCheck,
)
from hyperscale.kite.checks.repeatable_auditable_setup_for_3rd_party_access import (
    RepeatableAuditableSetupFor3rdPartyAccessCheck,
)
from hyperscale.kite.checks.require_mfa import RequireMfaCheck
from hyperscale.kite.checks.resolver_query_logs_enabled import (
    ResolverQueryLogsEnabledCheck,
)
from hyperscale.kite.checks.restore_testing import RestoreTestingCheck
from hyperscale.kite.checks.restricted_role_for_secrets_access import (
    RestrictedRoleForSecretsAccessCheck,
)
from hyperscale.kite.checks.review_pipeline_permissions_regularly import (
    ReviewPipelinePermissionsRegularlyCheck,
)
from hyperscale.kite.checks.root_access_keys_disallowed import (
    RootAccessKeysDisallowedCheck,
)
from hyperscale.kite.checks.root_access_testing import RootAccessTestingCheck
from hyperscale.kite.checks.root_account_monitoring import RootAccountMonitoringCheck
from hyperscale.kite.checks.root_actions_disallowed import RootActionsDisallowedCheck
from hyperscale.kite.checks.root_credentials_management_enabled import (
    RootCredentialsManagementEnabledCheck,
)
from hyperscale.kite.checks.root_credentials_security import (
    RootCredentialsSecurityCheck,
)
from hyperscale.kite.checks.root_mfa_enabled import RootMfaEnabledCheck
from hyperscale.kite.checks.rotate_encryption_keys import RotateEncryptionKeysCheck
from hyperscale.kite.checks.run_simulations import RunSimulationsCheck
from hyperscale.kite.checks.s3_bucket_acl_disabled import S3BucketAclDisabledCheck
from hyperscale.kite.checks.s3_confused_deputy_protection import (
    S3ConfusedDeputyProtectionCheck,
)
from hyperscale.kite.checks.scan_for_sensitive_data_in_dev import (
    ScanForSensitiveDataInDevCheck,
)
from hyperscale.kite.checks.scan_workloads_for_vulnerabilities import (
    ScanWorkloadsForVulnerabilitiesCheck,
)
from hyperscale.kite.checks.scim_protocol_used import ScimProtocolUsedCheck
from hyperscale.kite.checks.scp_prevents_adding_internet_access_to_vpc import (
    ScpPreventsAddingInternetAccessToVpcCheck,
)
from hyperscale.kite.checks.scp_prevents_cloudwatch_changes import (
    ScpPreventsCloudwatchChangesCheck,
)
from hyperscale.kite.checks.scp_prevents_common_admin_role_changes import (
    ScpPreventsCommonAdminRoleChangesCheck,
)
from hyperscale.kite.checks.scp_prevents_config_changes import (
    ScpPreventsConfigChangesCheck,
)
from hyperscale.kite.checks.scp_prevents_deleting_logs import (
    ScpPreventsDeletingLogsCheck,
)
from hyperscale.kite.checks.scp_prevents_guardduty_changes import (
    ScpPreventsGuarddutyChangesCheck,
)
from hyperscale.kite.checks.scp_prevents_leaving_org import ScpPreventsLeavingOrgCheck
from hyperscale.kite.checks.scp_prevents_ram_external_sharing import (
    ScpPreventsRamExternalSharingCheck,
)
from hyperscale.kite.checks.scp_prevents_ram_invitations import (
    ScpPreventsRamInvitationsCheck,
)
from hyperscale.kite.checks.scp_prevents_unencrypted_s3_uploads import (
    ScpPreventsUnencryptedS3UploadsCheck,
)
from hyperscale.kite.checks.secure_secrets_storage import SecureSecretsStorageCheck
from hyperscale.kite.checks.security_data_published_to_log_archive_account import (
    SecurityDataPublishedToLogArchiveAccountCheck,
)
from hyperscale.kite.checks.security_event_correlation import (
    SecurityEventCorrelationCheck,
)
from hyperscale.kite.checks.security_guardians_program import (
    SecurityGuardiansProgramCheck,
)
from hyperscale.kite.checks.security_ir_playbooks import SecurityIrPlaybooksCheck
from hyperscale.kite.checks.security_services_evaluation import (
    SecurityServicesEvaluationCheck,
)
from hyperscale.kite.checks.sensitivity_controls import SensitivityControlsCheck
from hyperscale.kite.checks.sns_confused_deputy_protection import (
    SnsConfusedDeputyProtectionCheck,
)
from hyperscale.kite.checks.sns_data_protection_policies import (
    SnsDataProtectionPoliciesCheck,
)
from hyperscale.kite.checks.sqs_confused_deputy_protection import (
    SqsConfusedDeputyProtectionCheck,
)
from hyperscale.kite.checks.tag_data_with_sensitivity_level import (
    TagDataWithSensitivityLevelCheck,
)
from hyperscale.kite.checks.tech_inventories_scanned import TechInventoriesScannedCheck
from hyperscale.kite.checks.threat_intelligence_monitoring import (
    ThreatIntelligenceMonitoringCheck,
)
from hyperscale.kite.checks.threat_model_pipelines import ThreatModelPipelinesCheck
from hyperscale.kite.checks.threat_modeling import ThreatModelingCheck
from hyperscale.kite.checks.tokenization_and_anonymization import (
    TokenizationAndAnonymizationCheck,
)
from hyperscale.kite.checks.train_for_application_security import (
    TrainForApplicationSecurityCheck,
)
from hyperscale.kite.checks.trusted_delegated_admins import TrustedDelegatedAdminsCheck
from hyperscale.kite.checks.use_a_kms import UseAKmsCheck
from hyperscale.kite.checks.use_centralized_idp import UseCentralizedIdpCheck
from hyperscale.kite.checks.use_customer_managed_keys import UseCustomerManagedKeysCheck
from hyperscale.kite.checks.use_hardened_images import UseHardenedImagesCheck
from hyperscale.kite.checks.use_identity_broker import UseIdentityBrokerCheck
from hyperscale.kite.checks.use_logs_for_alerting import UseLogsForAlertingCheck
from hyperscale.kite.checks.use_of_higher_level_services import (
    UseOfHigherLevelServicesCheck,
)
from hyperscale.kite.checks.use_private_link_for_vpc_routing import (
    UsePrivateLinkForVpcRoutingCheck,
)
from hyperscale.kite.checks.use_route53resolver_dns_firewall import (
    UseRoute53ResolverDnsFirewallCheck,
)
from hyperscale.kite.checks.use_service_encryption_at_rest import (
    UseServiceEncryptionAtRestCheck,
)
from hyperscale.kite.checks.validate_software_integrity import (
    ValidateSoftwareIntegrityCheck,
)
from hyperscale.kite.checks.vend_accounts_with_standardized_controls import (
    VendAccountsWithStandardizedControlsCheck,
)
from hyperscale.kite.checks.vpc_endpoints_enforce_data_perimeter import (
    VpcEndpointsEnforceDataPerimeterCheck,
)
from hyperscale.kite.checks.vpc_flow_logs_enabled import VpcFlowLogsEnabledCheck
from hyperscale.kite.checks.vulnerability_scanning_in_cicd_pipelines import (
    VulnerabilityScanningInCICDPipelinesCheck,
)
from hyperscale.kite.checks.waf_web_acl_logging_enabled import (
    WafWebAclLoggingEnabledCheck,
)
from hyperscale.kite.checks.well_defined_control_objectives import (
    WellDefinedControlObjectivesCheck,
)
from hyperscale.kite.checks.workload_dependency_updates import (
    WorkloadDependencyUpdatesCheck,
)


@dataclass
class Practice:
    name: str
    description: str
    checks: list[Check]


@dataclass
class Theme:
    name: str
    practices: list[Practice]


THEMES = [
    Theme(
        name="Management and Security Governance",
        practices=[
            Practice(
                name="Multi-Account Architecture",
                description=(
                    "Use accounts and organizational units to separate workloads with "
                    "different compliance requirement and to simplify applying common "
                    "controls across accounts, and restrict management account access"
                ),
                checks=[
                    AwsOrganizationsUsageCheck(),
                    AccountSeparationCheck(),
                    OuStructureCheck(),
                    ManagementAccountWorkloadsCheck(),
                    DelegatedAdminForSecurityServices(),
                    TrustedDelegatedAdminsCheck(),
                ],
            ),
            Practice(
                name="Root User Security",
                description=(
                    "Lock down the root user and avoid using the root account for "
                    "day-to-day tasks"
                ),
                checks=[
                    AvoidRootUsageCheck(),
                    RootCredentialsManagementEnabledCheck(),
                    NoRootAccessKeysCheck(),
                    RootMfaEnabledCheck(),
                    AccurateAccountContactDetailsCheck(),
                    RootAccessKeysDisallowedCheck(),
                    RootActionsDisallowedCheck(),
                    RootAccountMonitoringCheck(),
                    RootCredentialsSecurityCheck(),
                    RootAccessTestingCheck(),
                ],
            ),
            Practice(
                name="Control Objective Identification and Validation",
                description="Checks related to the identification and validation of "
                "control objectives",
                checks=[
                    WellDefinedControlObjectivesCheck(),
                    ControlImplementationValidationCheck(),
                ],
            ),
            Practice(
                name="Threat Intelligence",
                description="Checks related to the use of threat intelligence",
                checks=[
                    ThreatIntelligenceMonitoringCheck(),
                    TechInventoriesScannedCheck(),
                    WorkloadDependencyUpdatesCheck(),
                    AwsManagedServicesThreatIntelCheck(),
                ],
            ),
            Practice(
                name="Reducing Security Management Scope",
                description="Checks related to reducing the scope of security "
                "management",
                checks=[
                    UseOfHigherLevelServicesCheck(),
                    AwsControlDocumentationCheck(),
                    AwsServiceEvaluationCheck(),
                ],
            ),
            Practice(
                name="Automated Deployment of Standard Security Controls",
                description="Checks related to the automated deployment of standard "
                "security controls",
                checks=[
                    IacTemplatesCheck(),
                    IacVersionControlCheck(),
                    IacGuardrailsCheck(),
                    ProvideSecureConfigurationsCheck(),
                    VendAccountsWithStandardizedControlsCheck(),
                ],
            ),
            Practice(
                name="Threat modeling",
                description="Checks related to threat modeling practices and "
                "documentation",
                checks=[
                    ThreatModelingCheck(),
                ],
            ),
            Practice(
                name="Evaluate and implement new security services",
                description="Checks related to evaluating and implementing new "
                "security services",
                checks=[
                    SecurityServicesEvaluationCheck(),
                ],
            ),
        ],
    ),
    Theme(
        name="Identity and Access Management",
        practices=[
            Practice(
                name="Use strong sign-in mechanisms",
                description="Checks related to the use of strong sign-in mechanisms",
                checks=[
                    RequireMfaCheck(),
                    ComplexPasswordsCheck(),
                ],
            ),
            Practice(
                name="Use temporary credentials",
                description="Checks related to the use of temporary credentials",
                checks=[
                    NoAccessKeysCheck(),
                    NoKeyPairsCheck(),
                    NoIamUserAccessCheck(),
                ],
            ),
            Practice(
                name="Store and use secrets securely",
                description="Checks related to secure storage and use of secrets",
                checks=[
                    NoSecretsInAwsResourcesCheck(),
                    PreventAndDetectSecretsCheck(),
                    SecureSecretsStorageCheck(),
                    MonitorSecretsCheck(),
                    RestrictedRoleForSecretsAccessCheck(),
                ],
            ),
            Practice(
                name="Rely on a centralized identity provider",
                description="Checks related to using a centralized identity provider",
                checks=[
                    UseCentralizedIdpCheck(),
                    HrSystemIntegrationCheck(),
                ],
            ),
            Practice(
                name="Audit and rotate credentials periodically",
                description="Regularly audit and rotate credentials to maintain "
                "security and compliance",
                checks=[
                    CredentialRotationCheck(),
                    IdentityAuditCheck(),
                ],
            ),
            Practice(
                name="Employ user groups and attributes",
                description="Checks related to using user groups and attributes for "
                "permission management",
                checks=[
                    EmployUserGroupsAndAttributesCheck(),
                ],
            ),
            Practice(
                name="Define access requirements",
                description="Checks related to defining and documenting access "
                "requirements for resources and components",
                checks=[
                    DefineAccessRequirementsCheck(),
                ],
            ),
            Practice(
                name="Grant least privilege access",
                description="Checks related to granting least privilege access",
                checks=[
                    NoFullAdminPoliciesCheck(),
                    NoPolicyAllowsPrivilegeEscalationCheck(),
                    NoPermissiveRoleAssumptionCheck(),
                    NoFullAccessToSensitiveServicesCheck(),
                    NoReadonlyThirdPartyAccessCheck(),
                    AdminPrivilegesAreRestrictedCheck(),
                    LimitAccessToProductionEnvironmentsCheck(),
                    S3ConfusedDeputyProtectionCheck(),
                    SnsConfusedDeputyProtectionCheck(),
                    SqsConfusedDeputyProtectionCheck(),
                    LambdaConfusedDeputyProtectionCheck(),
                    KmsConfusedDeputyProtectionCheck(),
                ],
            ),
            Practice(
                name="Establish emergency access procedures",
                description="Checks related to establishing and maintaining emergency "
                "access procedures for critical failure scenarios",
                checks=[
                    EstablishedEmergencyAccessProceduresCheck(),
                ],
            ),
            Practice(
                name="Reduce permissions continuously",
                description="Checks related to reducing permissions continuously",
                checks=[
                    ActiveUnusedAccessAnalyzerCheck(),
                    RegularlyReviewPermissionsCheck(),
                ],
            ),
            Practice(
                name="Define permission guardrails for your organization",
                description="Checks related to defining permission guardrails for your "
                "organization",
                checks=[
                    RegionDenyScpCheck(),
                    ScpPreventsLeavingOrgCheck(),
                    ScpPreventsCommonAdminRoleChangesCheck(),
                    ScpPreventsCloudwatchChangesCheck(),
                    ScpPreventsConfigChangesCheck(),
                    ScpPreventsDeletingLogsCheck(),
                    ScpPreventsGuarddutyChangesCheck(),
                    ScpPreventsUnencryptedS3UploadsCheck(),
                    ScpPreventsAddingInternetAccessToVpcCheck(),
                    DelegateIamWithPermissionBoundariesCheck(),
                ],
            ),
            Practice(
                name="Manage access based on lifecycle",
                description="Checks related to managing access based on lifecycle",
                checks=[
                    AccessManagementLifecycleCheck(),
                    AccessManagementLifecycleImplementedCheck(),
                    ScimProtocolUsedCheck(),
                ],
            ),
            Practice(
                name="Analyze public and cross-account access",
                description="Checks related to analyzing public and cross-account "
                "access",
                checks=[
                    ActiveExternalAccessAnalyzerCheck(),
                    MonitorAndRespondToS3PublicAccessCheck(),
                    MaintainInventoryOfSharedResourcesCheck(),
                    ApprovalProcessForResourceSharingCheck(),
                ],
            ),
            Practice(
                name="Share resources securely within your organization",
                description="Checks related to sharing resources securely within your "
                "organization",
                checks=[
                    ScpPreventsRamExternalSharingCheck(),
                    ScpPreventsRamInvitationsCheck(),
                    S3BucketAclDisabledCheck(),
                    MigrateFromOaiCheck(),
                    DataPerimeterTrustedIdentitiesCheck(),
                    DataPerimeterConfusedDeputyProtectionCheck(),
                    DataPerimeterTrustedResourcesCheck(),
                    VpcEndpointsEnforceDataPerimeterCheck(),
                    DataPerimeterTrustedNetworksCheck(),
                ],
            ),
            Practice(
                name="Share resources securely with a 3rd party",
                description="Checks related to sharing resources securely with a 3rd "
                "party",
                checks=[
                    CrossAccountConfusedDeputyPreventionCheck(),
                    RepeatableAuditableSetupFor3rdPartyAccessCheck(),
                ],
            ),
        ],
    ),
    Theme(
        name="Security Logging and Monitoring",
        practices=[
            Practice(
                name="Configure service and application logging",
                description="Checks related to configuring service and application "
                "logging",
                checks=[
                    OrganizationalCloudTrailCheck(),
                    VpcFlowLogsEnabledCheck(),
                    ResolverQueryLogsEnabledCheck(),
                    LogRetentionCheck(),
                    WafWebAclLoggingEnabledCheck(),
                    ApiGatewayLoggingEnabledCheck(),
                    ElbLoggingEnabledCheck(),
                    EksControlPlaneLoggingEnabledCheck(),
                    NetworkFirewallLoggingEnabledCheck(),
                    RdsLoggingEnabledCheck(),
                    CloudfrontLoggingEnabledCheck(),
                    ConfigRecordingEnabledCheck(),
                    ImplementQueryingForLogsCheck(),
                    UseLogsForAlertingCheck(),
                ],
            ),
            Practice(
                name="Capture logs, findings and metrics in standardized locations",
                description="Checks related to capturing logs, findings and metrics in "
                "standardized locations",
                checks=[
                    SecurityDataPublishedToLogArchiveAccountCheck(),
                    DeployLogAnalysisToolsInAuditAccountCheck(),
                ],
            ),
            Practice(
                name="Correlate and enrich security alerts",
                description="Checks relating to automated correlation and enrichment "
                "of security alerts to accelerate incident response",
                checks=[
                    DetectiveEnabledCheck(),
                    SecurityEventCorrelationCheck(),
                ],
            ),
        ],
    ),
    Theme(
        name="Infrastructure Security",
        practices=[
            Practice(
                name="Create network layers",
                description="Checks related to creating network layers for your "
                "workloads",
                checks=[
                    CreateNetworkLayersCheck(),
                ],
            ),
            Practice(
                name="Control traffic flow within your network layers",
                description="Checks related to controlling traffic flow within your "
                "network layers",
                checks=[
                    ControlNetworkFlowWithNaclsCheck(),
                    ControlNetworkFlowsWithSGsCheck(),
                    ControlNetworkFlowsWithRouteTablesCheck(),
                    UsePrivateLinkForVpcRoutingCheck(),
                    UseRoute53ResolverDnsFirewallCheck(),
                ],
            ),
            Practice(
                name="Implement inspection-based protection",
                description="Checks related to implementing inspection-based "
                "protection for your workloads",
                checks=[
                    InspectHttpTrafficWithWafCheck(),
                    InspectTrafficWithNetworkFirewallCheck(),
                ],
            ),
            Practice(
                name="Perform vulnerability management",
                description="Checks related to performing vulnerability management for "
                "your workloads",
                checks=[
                    ScanWorkloadsForVulnerabilitiesCheck(),
                    RemediateVulnerabilitiesCheck(),
                    AutomatePatchManagementCheck(),
                    VulnerabilityScanningInCICDPipelinesCheck(),
                    AutomateMalwareAndThreatDetectionCheck(),
                ],
            ),
            Practice(
                name="Provision compute from hardened images",
                description="Checks related to provisioning compute from hardened "
                "images",
                checks=[
                    UseHardenedImagesCheck(),
                ],
            ),
            Practice(
                name="Reduce manual management and interactive access",
                description="Checks related to reducing manual management and "
                "interactive access",
                checks=[
                    NoRdpOrSshAccessCheck(),
                    AvoidInteractiveAccessCheck(),
                    AuditInteractiveAccessWithSSMCheck(),
                ],
            ),
            Practice(
                name="Validate software integrity",
                description="Checks related to validating software integrity",
                checks=[
                    ValidateSoftwareIntegrityCheck(),
                ],
            ),
        ],
    ),
    Theme(
        name="Data Protection",
        practices=[
            Practice(
                name="Understand your data classification scheme",
                description="Checks relating to the classification of data",
                checks=[
                    DocumentedDataClassificationSchemeCheck(),
                    DataCatalogCheck(),
                    TagDataWithSensitivityLevelCheck(),
                ],
            ),
            Practice(
                name="Apply data protection controls based on data sensitivity",
                description="Checks related to applying data protection controls based "
                "on data sensitivity levels",
                checks=[
                    IsolationBoundariesCheck(),
                    SensitivityControlsCheck(),
                    TokenizationAndAnonymizationCheck(),
                ],
            ),
            Practice(
                name="Automate identification and classification",
                description="Checks related to identifying and classifying data",
                checks=[
                    CwDataProtectionPoliciesCheck(),
                    SnsDataProtectionPoliciesCheck(),
                    DetectSensitiveDataTransformCheck(),
                    MacieScansForSensitiveDataCheck(),
                    ScanForSensitiveDataInDevCheck(),
                ],
            ),
            Practice(
                name="Define scalable data lifecycle management",
                description="Checks related to scalable data lifecycle management",
                checks=[
                    AutomateS3DataRetentionCheck(),
                    AutomateDdbDataRetentionCheck(),
                    ImplementRetentionPoliciesCheck(),
                    DetectMissingAutomatedLifecycleManagementCheck(),
                ],
            ),
            Practice(
                name="Implement secure key management",
                description="Checks related to the storage, rotation, access control, "
                "and monitoring of key material used to secure data at rest for your "
                "workloads.",
                checks=[
                    UseAKmsCheck(),
                    NoHumanAccessToUnencryptedKeyMaterialCheck(),
                    RotateEncryptionKeysCheck(),
                    MonitorKeyUsageCheck(),
                    KeyAccessControlCheck(),
                ],
            ),
            Practice(
                name="Enforce encryption at rest",
                description="Checks related to enforcing encryption at rest",
                checks=[
                    UseServiceEncryptionAtRestCheck(),
                    UseCustomerManagedKeysCheck(),
                ],
            ),
            Practice(
                name="Automate data at rest protection",
                description="Checks related to automating data at rest protection",
                checks=[
                    DetectEncryptionAtRestMisconfigCheck(),
                    EnforceDataProtectionAtRestWithPolicyAsCodeCheck(),
                    AutomateDataAtRestProtectionWithGuardDutyCheck(),
                    AirGappedBackupVaultCheck(),
                    RestoreTestingCheck(),
                ],
            ),
            Practice(
                name="Enforce access control",
                description="Checks related to enforcing access control",
                checks=[
                    ImplementVersioningAndObjectLockingCheck(),
                ],
            ),
            Practice(
                name="Implement secure key and certificate management",
                description="Checks relating to the secure management of TLS "
                "certificates and their private keys",
                checks=[
                    CertDeploymentAndRenewalCheck(),
                    ProtectRootCaCheck(),
                    EstablishLoggingAndAuditTrailsForPrivateCACheck(),
                ],
            ),
            Practice(
                name="Enforce encryption in transit",
                description="Checks related to enforcing encryption in transit",
                checks=[
                    EnforceHttpsCheck(),
                    AvoidInsecureSslCiphersCheck(),
                ],
            ),
            Practice(
                name="Authenticate network communications",
                description="Checks related to authenticating network communications",
                checks=[
                    DefineAndDocumentWorkloadNetworkFlowsCheck(),
                    ImplementAuthAcrossServicesCheck(),
                    MonitorNetworkTrafficForUnauthorizedAccessCheck(),
                ],
            ),
        ],
    ),
    Theme(
        name="Threat Detection and Incident Response",
        practices=[
            Practice(
                name="Initiate remediation for non-compliant resources",
                description="The steps to remedidate when resources are detected to be "
                "non-compliant are defined, programmitically, along with resource "
                "configuration standards so that they can be initiated either manually "
                "or automatically when resources are found to be non-compliant",
                checks=[
                    AutoRemediateNonCompliantResourcesCheck(),
                ],
            ),
            Practice(
                name="Identify key personnel and external resources",
                description="Checks related to identifying key personnel and external "
                "resources",
                checks=[
                    CaptureKeyContactsCheck(),
                ],
            ),
            Practice(
                name="Develop incident management plans",
                description="Checks related to developing incident management plans",
                checks=[
                    IncidentResponsePlansCheck(),
                ],
            ),
            Practice(
                name="Prepare forensic capabilities",
                description="Checks related to preparing forensic capabilities",
                checks=[
                    ForensicsOuCheck(),
                    AutomateForensicsCheck(),
                ],
            ),
            Practice(
                name="Develop and test security incident response playbooks",
                description="Checks related to developing security incident response "
                "playbooks",
                checks=[
                    SecurityIrPlaybooksCheck(),
                ],
            ),
            Practice(
                name="Pre-provision access",
                description="Checks related to pre-provisioning access for incident "
                "response",
                checks=[
                    UseIdentityBrokerCheck(),
                ],
            ),
            Practice(
                name="Pre-deploy tools",
                description="Checks related to pre-deploying tools required to support "
                "incident response and security operations",
                checks=[
                    PreDeployToolsCheck(),
                ],
            ),
            Practice(
                name="Run simulations",
                description="Checks related to running regular simulations to test and "
                "validate incident response capabilities",
                checks=[
                    RunSimulationsCheck(),
                ],
            ),
            Practice(
                name="Establish a framework for learning from incidents",
                description="Checks related to establishing frameworks and processes "
                "for learning from incidents and applying lessons learned",
                checks=[
                    LessonsLearnedFrameworkCheck(),
                ],
            ),
        ],
    ),
    Theme(
        name="Application Security",
        practices=[
            Practice(
                name="Train for application security",
                description="Checks related to training for application security",
                checks=[
                    TrainForApplicationSecurityCheck(),
                ],
            ),
            Practice(
                name="Automate testing throughout the development and release "
                "lifecycle",
                description="Checks relating to the automated testing for security "
                "properties throughout the development and release lifecycle",
                checks=[
                    PerformSASTCheck(),
                    PerformDASTCheck(),
                    AutomatedSecurityTestsCheck(),
                ],
            ),
            Practice(
                name="Perform regular penetration testing",
                description="Checks related to performing regular penetration testing",
                checks=[
                    PenetrationTestingCheck(),
                ],
            ),
            Practice(
                name="Conduct code reviews",
                description="Checks related to conducting code reviews to detect "
                "security vulnerabilities",
                checks=[
                    CodeReviewsCheck(),
                ],
            ),
            Practice(
                name="Centralize services for packages and dependencies",
                description="Checks related to using centralized services for packages "
                "and dependencies",
                checks=[
                    CentralizedArtifactReposCheck(),
                ],
            ),
            Practice(
                name="Deploy software programmatically",
                description="Checks related to deploying software programmatically",
                checks=[
                    AutomateDeploymentsCheck(),
                    ImmutableBuildsCheck(),
                ],
            ),
            Practice(
                name="Regularly assess security properties of the pipelines",
                description="The pipelines you use to build and deploy your software "
                "should follow the same recommended practices as any other workload in "
                "your environment",
                checks=[
                    PipelinesUseLeastPrivilegeCheck(),
                    ReviewPipelinePermissionsRegularlyCheck(),
                    ThreatModelPipelinesCheck(),
                ],
            ),
            Practice(
                name="Build a program that embeds security ownership in workload teams",
                description="Checks related to building a program that embeds security "
                "ownership in workload teams",
                checks=[
                    SecurityGuardiansProgramCheck(),
                ],
            ),
        ],
    ),
]


def all_checks():
    checks = []
    for theme in THEMES:
        for practice in theme.practices:
            checks.extend(practice.checks)
    return checks


def find_check_by_id(check_id):
    for check in all_checks():
        if check.check_id == check_id:
            return check
    return None


__all__ = ["CheckStatus", "CheckResult"]
