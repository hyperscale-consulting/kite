from dataclasses import dataclass

from hyperscale.kite.checks import AccessManagementLifecycleCheck
from hyperscale.kite.checks import AccessManagementLifecycleImplementedCheck
from hyperscale.kite.checks import AccountSeparationCheck
from hyperscale.kite.checks import AccountStandardsCheck
from hyperscale.kite.checks import AccurateAccountContactDetailsCheck
from hyperscale.kite.checks import ActiveExternalAccessAnalyzerCheck
from hyperscale.kite.checks import ActiveUnusedAccessAnalyzerCheck
from hyperscale.kite.checks import AdminPrivilegesAreRestrictedCheck
from hyperscale.kite.checks import AirGappedBackupVaultCheck
from hyperscale.kite.checks import ApprovalProcessForResourceSharingCheck
from hyperscale.kite.checks import AuditInteractiveAccessWithSSMCheck
from hyperscale.kite.checks import AutomateDataAtRestProtectionWithGuardDutyCheck
from hyperscale.kite.checks import AutomateDdbDataRetentionCheck
from hyperscale.kite.checks import AutomateDeploymentsCheck
from hyperscale.kite.checks import AutomatedSecurityTestsCheck
from hyperscale.kite.checks import AutomateForensicsCheck
from hyperscale.kite.checks import AutomateMalwareAndThreatDetectionCheck
from hyperscale.kite.checks import AutomatePatchManagementCheck
from hyperscale.kite.checks import AutomateS3DataRetentionCheck
from hyperscale.kite.checks import AutoRemediateNonCompliantResourcesCheck
from hyperscale.kite.checks import AvoidInsecureSslCiphersCheck
from hyperscale.kite.checks import AvoidInteractiveAccessCheck
from hyperscale.kite.checks import AvoidRootUsageCheck
from hyperscale.kite.checks import AwsControlDocumentationCheck
from hyperscale.kite.checks import AwsManagedServicesThreatIntelCheck
from hyperscale.kite.checks import AwsOrganizationsUsageCheck
from hyperscale.kite.checks import AwsServiceEvaluationCheck
from hyperscale.kite.checks import CaptureKeyContactsCheck
from hyperscale.kite.checks import CentralizedArtifactReposCheck
from hyperscale.kite.checks import CertDeploymentAndRenewalCheck
from hyperscale.kite.checks import Check
from hyperscale.kite.checks import CloudfrontLoggingEnabledCheck
from hyperscale.kite.checks import CodeReviewsCheck
from hyperscale.kite.checks import ComplexPasswordsCheck
from hyperscale.kite.checks import ConfigRecordingEnabledCheck
from hyperscale.kite.checks import ControlImplementationValidationCheck
from hyperscale.kite.checks import ControlNetworkFlowsWithRouteTablesCheck
from hyperscale.kite.checks import ControlNetworkFlowsWithSGsCheck
from hyperscale.kite.checks import ControlNetworkFlowWithNaclsCheck
from hyperscale.kite.checks import ControlTowerCheck
from hyperscale.kite.checks import CreateNetworkLayersCheck
from hyperscale.kite.checks import CredentialRotationCheck
from hyperscale.kite.checks import CrossAccountConfusedDeputyPreventionCheck
from hyperscale.kite.checks import CwDataProtectionPoliciesCheck
from hyperscale.kite.checks import DataCatalogCheck
from hyperscale.kite.checks import DataPerimeterConfusedDeputyProtectionCheck
from hyperscale.kite.checks import DataPerimeterTrustedIdentitiesCheck
from hyperscale.kite.checks import DataPerimeterTrustedNetworksCheck
from hyperscale.kite.checks import DataPerimeterTrustedResourcesCheck
from hyperscale.kite.checks import DefineAccessRequirementsCheck
from hyperscale.kite.checks import DefineAndDocumentWorkloadNetworkFlowsCheck
from hyperscale.kite.checks import DelegatedAdminForSecurityServices
from hyperscale.kite.checks import DelegateIamWithPermissionBoundariesCheck
from hyperscale.kite.checks import DeployLogAnalysisToolsInAuditAccountCheck
from hyperscale.kite.checks import DetectEncryptionAtRestMisconfigCheck
from hyperscale.kite.checks import DetectiveEnabledCheck
from hyperscale.kite.checks import DetectMissingAutomatedLifecycleManagementCheck
from hyperscale.kite.checks import DetectSensitiveDataTransformCheck
from hyperscale.kite.checks import DfdsCheck
from hyperscale.kite.checks import DocumentedDataClassificationSchemeCheck
from hyperscale.kite.checks import EksControlPlaneLoggingEnabledCheck
from hyperscale.kite.checks import ElbLoggingEnabledCheck
from hyperscale.kite.checks import EmployUserGroupsAndAttributesCheck
from hyperscale.kite.checks import EnforceDataProtectionAtRestWithPolicyAsCodeCheck
from hyperscale.kite.checks import EnforceHttpsCheck
from hyperscale.kite.checks import EstablishedEmergencyAccessProceduresCheck
from hyperscale.kite.checks import EstablishLoggingAndAuditTrailsForPrivateCACheck
from hyperscale.kite.checks import ForensicsOuCheck
from hyperscale.kite.checks import HrSystemIntegrationCheck
from hyperscale.kite.checks import IacGuardrailsCheck
from hyperscale.kite.checks import IacTemplatesCheck
from hyperscale.kite.checks import IacVersionControlCheck
from hyperscale.kite.checks import IdentityAuditCheck
from hyperscale.kite.checks import ImmutableBuildsCheck
from hyperscale.kite.checks import ImplementAuthAcrossServicesCheck
from hyperscale.kite.checks import ImplementQueryingForLogsCheck
from hyperscale.kite.checks import ImplementRetentionPoliciesCheck
from hyperscale.kite.checks import ImplementVersioningAndObjectLockingCheck
from hyperscale.kite.checks import IncidentResponsePlansCheck
from hyperscale.kite.checks import InspectHttpTrafficWithWafCheck
from hyperscale.kite.checks import InspectTrafficWithNetworkFirewallCheck
from hyperscale.kite.checks import IsolationBoundariesCheck
from hyperscale.kite.checks import KeyAccessControlCheck
from hyperscale.kite.checks import KmsConfusedDeputyProtectionCheck
from hyperscale.kite.checks import LambdaConfusedDeputyProtectionCheck
from hyperscale.kite.checks import LessonsLearnedFrameworkCheck
from hyperscale.kite.checks import LimitAccessToProductionEnvironmentsCheck
from hyperscale.kite.checks import LogRetentionCheck
from hyperscale.kite.checks import MacieScansForSensitiveDataCheck
from hyperscale.kite.checks import MaintainInventoryOfSharedResourcesCheck
from hyperscale.kite.checks import ManagementAccountWorkloadsCheck
from hyperscale.kite.checks import MigrateFromOaiCheck
from hyperscale.kite.checks import MonitorAndRespondToS3PublicAccessCheck
from hyperscale.kite.checks import MonitorKeyUsageCheck
from hyperscale.kite.checks import MonitorNetworkTrafficForUnauthorizedAccessCheck
from hyperscale.kite.checks import MonitorSecretsCheck
from hyperscale.kite.checks import NetworkFirewallLoggingEnabledCheck
from hyperscale.kite.checks import NoAccessKeysCheck
from hyperscale.kite.checks import NoFullAccessToSensitiveServicesCheck
from hyperscale.kite.checks import NoFullAdminPoliciesCheck
from hyperscale.kite.checks import NoHumanAccessToUnencryptedKeyMaterialCheck
from hyperscale.kite.checks import NoIamUserAccessCheck
from hyperscale.kite.checks import NoKeyPairsCheck
from hyperscale.kite.checks import NoPermissiveRoleAssumptionCheck
from hyperscale.kite.checks import NoPolicyAllowsPrivilegeEscalationCheck
from hyperscale.kite.checks import NoRdpOrSshAccessCheck
from hyperscale.kite.checks import NoReadonlyThirdPartyAccessCheck
from hyperscale.kite.checks import NoRootAccessKeysCheck
from hyperscale.kite.checks import NoSecretsInAwsResourcesCheck
from hyperscale.kite.checks import OrganizationalCloudTrailCheck
from hyperscale.kite.checks import OuStructureCheck
from hyperscale.kite.checks import PenetrationTestingCheck
from hyperscale.kite.checks import PerformDASTCheck
from hyperscale.kite.checks import PerformSASTCheck
from hyperscale.kite.checks import PipelinesUseLeastPrivilegeCheck
from hyperscale.kite.checks import PreDeployToolsCheck
from hyperscale.kite.checks import PreventAndDetectSecretsCheck
from hyperscale.kite.checks import ProtectRootCaCheck
from hyperscale.kite.checks import RdsLoggingEnabledCheck
from hyperscale.kite.checks import RegionDenyScpCheck
from hyperscale.kite.checks import RegularlyReviewPermissionsCheck
from hyperscale.kite.checks import RemediateVulnerabilitiesCheck
from hyperscale.kite.checks import RepeatableAuditableSetupFor3rdPartyAccessCheck
from hyperscale.kite.checks import RequireMfaCheck
from hyperscale.kite.checks import ResolverQueryLogsEnabledCheck
from hyperscale.kite.checks import RestoreTestingCheck
from hyperscale.kite.checks import RestrictedRoleForSecretsAccessCheck
from hyperscale.kite.checks import ReviewPipelinePermissionsRegularlyCheck
from hyperscale.kite.checks import RootAccessKeysDisallowedCheck
from hyperscale.kite.checks import RootAccessTestingCheck
from hyperscale.kite.checks import RootAccountMonitoringCheck
from hyperscale.kite.checks import RootActionsDisallowedCheck
from hyperscale.kite.checks import RootCredentialsManagementEnabledCheck
from hyperscale.kite.checks import RootCredentialsSecurityCheck
from hyperscale.kite.checks import RootMfaEnabledCheck
from hyperscale.kite.checks import RotateEncryptionKeysCheck
from hyperscale.kite.checks import RunSimulationsCheck
from hyperscale.kite.checks import S3BucketAclDisabledCheck
from hyperscale.kite.checks import S3ConfusedDeputyProtectionCheck
from hyperscale.kite.checks import ScanForSensitiveDataInDevCheck
from hyperscale.kite.checks import ScanWorkloadsForVulnerabilitiesCheck
from hyperscale.kite.checks import ScimProtocolUsedCheck
from hyperscale.kite.checks import ScpPreventsAddingInternetAccessToVpcCheck
from hyperscale.kite.checks import ScpPreventsCloudwatchChangesCheck
from hyperscale.kite.checks import ScpPreventsCommonAdminRoleChangesCheck
from hyperscale.kite.checks import ScpPreventsConfigChangesCheck
from hyperscale.kite.checks import ScpPreventsDeletingLogsCheck
from hyperscale.kite.checks import ScpPreventsGuarddutyChangesCheck
from hyperscale.kite.checks import ScpPreventsLeavingOrgCheck
from hyperscale.kite.checks import ScpPreventsRamExternalSharingCheck
from hyperscale.kite.checks import ScpPreventsRamInvitationsCheck
from hyperscale.kite.checks import ScpPreventsUnencryptedS3UploadsCheck
from hyperscale.kite.checks import SecureSecretsStorageCheck
from hyperscale.kite.checks import SecurityDataPublishedToLogArchiveAccountCheck
from hyperscale.kite.checks import SecurityEventCorrelationCheck
from hyperscale.kite.checks import SecurityGuardiansProgramCheck
from hyperscale.kite.checks import SecurityIrPlaybooksCheck
from hyperscale.kite.checks import SecurityRisksCheck
from hyperscale.kite.checks import SecurityServicesEvaluationCheck
from hyperscale.kite.checks import SensitivityControlsCheck
from hyperscale.kite.checks import ServiceCatalogCheck
from hyperscale.kite.checks import SnsConfusedDeputyProtectionCheck
from hyperscale.kite.checks import SnsDataProtectionPoliciesCheck
from hyperscale.kite.checks import SqsConfusedDeputyProtectionCheck
from hyperscale.kite.checks import TagDataWithSensitivityLevelCheck
from hyperscale.kite.checks import TechInventoriesScannedCheck
from hyperscale.kite.checks import ThreatIntelligenceMonitoringCheck
from hyperscale.kite.checks import ThreatModelingCheck
from hyperscale.kite.checks import ThreatModelPipelinesCheck
from hyperscale.kite.checks import TokenizationAndAnonymizationCheck
from hyperscale.kite.checks import TrainForApplicationSecurityCheck
from hyperscale.kite.checks import TrustedDelegatedAdminsCheck
from hyperscale.kite.checks import UseAKmsCheck
from hyperscale.kite.checks import UseCentralizedIdpCheck
from hyperscale.kite.checks import UseCustomerManagedKeysCheck
from hyperscale.kite.checks import UseHardenedImagesCheck
from hyperscale.kite.checks import UseIdentityBrokerCheck
from hyperscale.kite.checks import UseLogsForAlertingCheck
from hyperscale.kite.checks import UseOfHigherLevelServicesCheck
from hyperscale.kite.checks import UsePrivateLinkForVpcRoutingCheck
from hyperscale.kite.checks import UseRoute53ResolverDnsFirewallCheck
from hyperscale.kite.checks import UseServiceEncryptionAtRestCheck
from hyperscale.kite.checks import ValidateSoftwareIntegrityCheck
from hyperscale.kite.checks import VpcEndpointsEnforceDataPerimeterCheck
from hyperscale.kite.checks import VpcFlowLogsEnabledCheck
from hyperscale.kite.checks import VulnerabilityScanningInCICDPipelinesCheck
from hyperscale.kite.checks import WafWebAclLoggingEnabledCheck
from hyperscale.kite.checks import WellDefinedControlObjectivesCheck
from hyperscale.kite.checks import WorkloadDependencyUpdatesCheck


@dataclass
class CheckTheme:
    name: str
    description: str
    checks: list[Check]


CHECK_THEMES = [
    CheckTheme(
        name="Multi-Account Architecture",
        description="Checks related to organizational structure, landing zone and "
        "guardrails",
        checks=[
            AwsOrganizationsUsageCheck(),
            AccountSeparationCheck(),
            OuStructureCheck(),
            ManagementAccountWorkloadsCheck(),
            DelegatedAdminForSecurityServices(),
            TrustedDelegatedAdminsCheck(),
        ],
    ),
    CheckTheme(
        name="Root User Security",
        description="Checks related to the security of the root user",
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
    CheckTheme(
        name="Control Objective Identification and Validation",
        description="Checks related to the identification and validation of control "
        "objectives",
        checks=[
            WellDefinedControlObjectivesCheck(),
            ControlImplementationValidationCheck(),
        ],
    ),
    CheckTheme(
        name="Threat Intelligence",
        description="Checks related to the use of threat intelligence",
        checks=[
            ThreatIntelligenceMonitoringCheck(),
            TechInventoriesScannedCheck(),
            WorkloadDependencyUpdatesCheck(),
            AwsManagedServicesThreatIntelCheck(),
        ],
    ),
    CheckTheme(
        name="Reducing Security Management Scope",
        description="Checks related to reducing the scope of security management",
        checks=[
            UseOfHigherLevelServicesCheck(),
            AwsControlDocumentationCheck(),
            AwsServiceEvaluationCheck(),
        ],
    ),
    CheckTheme(
        name="Automated Deployment of Standard Security Controls",
        description="Checks related to the automated deployment of standard security "
        "controls",
        checks=[
            IacTemplatesCheck(),
            IacVersionControlCheck(),
            IacGuardrailsCheck(),
            ServiceCatalogCheck(),
            AccountStandardsCheck(),
            ControlTowerCheck(),
        ],
    ),
    CheckTheme(
        name="Threat modeling",
        description="Checks related to threat modeling practices and documentation",
        checks=[
            ThreatModelingCheck(),
            DfdsCheck(),
            SecurityRisksCheck(),
        ],
    ),
    CheckTheme(
        name="Evaluate and implement new security services",
        description="Checks related to evaluating and implementing new security "
        "services",
        checks=[
            SecurityServicesEvaluationCheck(),
        ],
    ),
    CheckTheme(
        name="Use strong sign-in mechanisms",
        description="Checks related to the use of strong sign-in mechanisms",
        checks=[
            RequireMfaCheck(),
            ComplexPasswordsCheck(),
        ],
    ),
    CheckTheme(
        name="Use temporary credentials",
        description="Checks related to the use of temporary credentials",
        checks=[
            NoAccessKeysCheck(),
            NoKeyPairsCheck(),
            NoIamUserAccessCheck(),
        ],
    ),
    CheckTheme(
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
    CheckTheme(
        name="Rely on a centralized identity provider",
        description="Checks related to using a centralized identity provider",
        checks=[
            UseCentralizedIdpCheck(),
            HrSystemIntegrationCheck(),
        ],
    ),
    CheckTheme(
        name="Audit and rotate credentials periodically",
        description="Regularly audit and rotate credentials to maintain security and "
        "compliance",
        checks=[
            CredentialRotationCheck(),
            IdentityAuditCheck(),
        ],
    ),
    CheckTheme(
        name="Employ user groups and attributes",
        description="Checks related to using user groups and attributes for permission "
        "management",
        checks=[
            EmployUserGroupsAndAttributesCheck(),
        ],
    ),
    CheckTheme(
        name="Define access requirements",
        description="Checks related to defining and documenting access requirements "
        "for resources and components",
        checks=[
            DefineAccessRequirementsCheck(),
        ],
    ),
    CheckTheme(
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
    CheckTheme(
        name="Establish emergency access procedures",
        description="Checks related to establishing and maintaining emergency access "
        "procedures for critical failure scenarios",
        checks=[
            EstablishedEmergencyAccessProceduresCheck(),
        ],
    ),
    CheckTheme(
        name="Reduce permissions continuously",
        description="Checks related to reducing permissions continuously",
        checks=[
            ActiveUnusedAccessAnalyzerCheck(),
            RegularlyReviewPermissionsCheck(),
        ],
    ),
    CheckTheme(
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
    CheckTheme(
        name="Manage access based on lifecycle",
        description="Checks related to managing access based on lifecycle",
        checks=[
            AccessManagementLifecycleCheck(),
            AccessManagementLifecycleImplementedCheck(),
            ScimProtocolUsedCheck(),
        ],
    ),
    CheckTheme(
        name="Analyze public and cross-account access",
        description="Checks related to analyzing public and cross-account access",
        checks=[
            ActiveExternalAccessAnalyzerCheck(),
            MonitorAndRespondToS3PublicAccessCheck(),
            MaintainInventoryOfSharedResourcesCheck(),
            ApprovalProcessForResourceSharingCheck(),
        ],
    ),
    CheckTheme(
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
    CheckTheme(
        name="Share resources securely with a 3rd party",
        description="Checks related to sharing resources securely with a 3rd party",
        checks=[
            CrossAccountConfusedDeputyPreventionCheck(),
            RepeatableAuditableSetupFor3rdPartyAccessCheck(),
        ],
    ),
    CheckTheme(
        name="Configure service and application logging",
        description="Checks related to configuring service and application logging",
        checks=[
            OrganizationalCloudTrailCheck(),
            VpcFlowLogsEnabledCheck(),
            ResolverQueryLogsEnabledCheck(),
            LogRetentionCheck(),
            WafWebAclLoggingEnabledCheck(),
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
    CheckTheme(
        name="Capture logs, findings and metrics in standardized locations",
        description="Checks related to capturing logs, findings and metrics in "
        "standardized locations",
        checks=[
            SecurityDataPublishedToLogArchiveAccountCheck(),
            DeployLogAnalysisToolsInAuditAccountCheck(),
        ],
    ),
    CheckTheme(
        name="Correlate and enrich security alerts",
        description="Checks relating to automated correlation and enrichment of "
        "security alerts to accelerate incident response",
        checks=[
            DetectiveEnabledCheck(),
            SecurityEventCorrelationCheck(),
        ],
    ),
    CheckTheme(
        name="Initiate remediation for non-compliant resources",
        description="The steps to remedidate when resources are detected to be "
        "non-compliant are defined, programmitically, along with resource "
        "configuration standards so that they can be initiated either manually or "
        "automatically when resources are found to be non-compliant",
        checks=[
            AutoRemediateNonCompliantResourcesCheck(),
        ],
    ),
    CheckTheme(
        name="Create network layers",
        description="Checks related to creating network layers for your workloads",
        checks=[
            CreateNetworkLayersCheck(),
        ],
    ),
    CheckTheme(
        name="Control traffic flow within your network layers",
        description="Checks related to controlling traffic flow within your network "
        "layers",
        checks=[
            ControlNetworkFlowWithNaclsCheck(),
            ControlNetworkFlowsWithSGsCheck(),
            ControlNetworkFlowsWithRouteTablesCheck(),
            UsePrivateLinkForVpcRoutingCheck(),
            UseRoute53ResolverDnsFirewallCheck(),
        ],
    ),
    CheckTheme(
        name="Implement inspection-based protection",
        description="Checks related to implementing inspection-based protection for "
        "your workloads",
        checks=[
            InspectHttpTrafficWithWafCheck(),
            InspectTrafficWithNetworkFirewallCheck(),
        ],
    ),
    CheckTheme(
        name="Perform vulnerability management",
        description="Checks related to performing vulnerability management for your "
        "workloads",
        checks=[
            ScanWorkloadsForVulnerabilitiesCheck(),
            RemediateVulnerabilitiesCheck(),
            AutomatePatchManagementCheck(),
            VulnerabilityScanningInCICDPipelinesCheck(),
            AutomateMalwareAndThreatDetectionCheck(),
        ],
    ),
    CheckTheme(
        name="Provision compute from hardened images",
        description="Checks related to provisioning compute from hardened images",
        checks=[
            UseHardenedImagesCheck(),
        ],
    ),
    CheckTheme(
        name="Reduce manual management and interactive access",
        description="Checks related to reducing manual management and interactive "
        "access",
        checks=[
            NoRdpOrSshAccessCheck(),
            AvoidInteractiveAccessCheck(),
            AuditInteractiveAccessWithSSMCheck(),
        ],
    ),
    CheckTheme(
        name="Validate software integrity",
        description="Checks related to validating software integrity",
        checks=[
            ValidateSoftwareIntegrityCheck(),
        ],
    ),
    CheckTheme(
        name="Understand your data classification scheme",
        description="Checks relating to the classification of data",
        checks=[
            DocumentedDataClassificationSchemeCheck(),
            DataCatalogCheck(),
            TagDataWithSensitivityLevelCheck(),
        ],
    ),
    CheckTheme(
        name="Apply data protection controls based on data sensitivity",
        description="Checks related to applying data protection controls based on data "
        "sensitivity levels",
        checks=[
            IsolationBoundariesCheck(),
            SensitivityControlsCheck(),
            TokenizationAndAnonymizationCheck(),
        ],
    ),
    CheckTheme(
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
    CheckTheme(
        name="Define scalable data lifecycle management",
        description="Checks related to scalable data lifecycle management",
        checks=[
            AutomateS3DataRetentionCheck(),
            AutomateDdbDataRetentionCheck(),
            ImplementRetentionPoliciesCheck(),
            DetectMissingAutomatedLifecycleManagementCheck(),
        ],
    ),
    CheckTheme(
        name="Implement secure key management",
        description="Checks related to the storage, rotation, access control, and "
        "monitoring of key material used to secure data at rest for your workloads.",
        checks=[
            UseAKmsCheck(),
            NoHumanAccessToUnencryptedKeyMaterialCheck(),
            RotateEncryptionKeysCheck(),
            MonitorKeyUsageCheck(),
            KeyAccessControlCheck(),
        ],
    ),
    CheckTheme(
        name="Enforce encryption at rest",
        description="Checks related to enforcing encryption at rest",
        checks=[
            UseServiceEncryptionAtRestCheck(),
            UseCustomerManagedKeysCheck(),
        ],
    ),
    CheckTheme(
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
    CheckTheme(
        name="Enforce access control",
        description="Checks related to enforcing access control",
        checks=[
            ImplementVersioningAndObjectLockingCheck(),
        ],
    ),
    CheckTheme(
        name="Implement secure key and certificate management",
        description="Checks relating to the secure management of TLS certificates and "
        "their private keys",
        checks=[
            CertDeploymentAndRenewalCheck(),
            ProtectRootCaCheck(),
            EstablishLoggingAndAuditTrailsForPrivateCACheck(),
        ],
    ),
    CheckTheme(
        name="Enforce encryption in transit",
        description="Checks related to enforcing encryption in transit",
        checks=[
            EnforceHttpsCheck(),
            AvoidInsecureSslCiphersCheck(),
        ],
    ),
    CheckTheme(
        name="Authenticate network communications",
        description="Checks related to authenticating network communications",
        checks=[
            DefineAndDocumentWorkloadNetworkFlowsCheck(),
            ImplementAuthAcrossServicesCheck(),
            MonitorNetworkTrafficForUnauthorizedAccessCheck(),
        ],
    ),
    CheckTheme(
        name="Identify key personnel and external resources",
        description="Checks related to identifying key personnel and external "
        "resources",
        checks=[
            CaptureKeyContactsCheck(),
        ],
    ),
    CheckTheme(
        name="Develop incident management plans",
        description="Checks related to developing incident management plans",
        checks=[
            IncidentResponsePlansCheck(),
        ],
    ),
    CheckTheme(
        name="Prepare forensic capabilities",
        description="Checks related to preparing forensic capabilities",
        checks=[
            ForensicsOuCheck(),
            AutomateForensicsCheck(),
        ],
    ),
    CheckTheme(
        name="Develop and test security incident response playbooks",
        description="Checks related to developing security incident response playbooks",
        checks=[
            SecurityIrPlaybooksCheck(),
        ],
    ),
    CheckTheme(
        name="Pre-provision access",
        description="Checks related to pre-provisioning access for incident response",
        checks=[
            UseIdentityBrokerCheck(),
        ],
    ),
    CheckTheme(
        name="Pre-deploy tools",
        description="Checks related to pre-deploying tools required to support "
        "incident response and security operations",
        checks=[
            PreDeployToolsCheck(),
        ],
    ),
    CheckTheme(
        name="Run simulations",
        description="Checks related to running regular simulations to test and "
        "validate incident response capabilities",
        checks=[
            RunSimulationsCheck(),
        ],
    ),
    CheckTheme(
        name="Establish a framework for learning from incidents",
        description="Checks related to establishing frameworks and processes for "
        "learning from incidents and applying lessons learned",
        checks=[
            LessonsLearnedFrameworkCheck(),
        ],
    ),
    CheckTheme(
        name="Train for application security",
        description="Checks related to training for application security",
        checks=[
            TrainForApplicationSecurityCheck(),
        ],
    ),
    CheckTheme(
        name="Automate testing throughout the development and release lifecycle",
        description="Checks relating to the automated testing for security properties "
        "throughout the development and release lifecycle",
        checks=[
            PerformSASTCheck(),
            PerformDASTCheck(),
            AutomatedSecurityTestsCheck(),
        ],
    ),
    CheckTheme(
        name="Perform regular penetration testing",
        description="Checks related to performing regular penetration testing",
        checks=[
            PenetrationTestingCheck(),
        ],
    ),
    CheckTheme(
        name="Conduct code reviews",
        description="Checks related to conducting code reviews to detect security "
        "vulnerabilities",
        checks=[
            CodeReviewsCheck(),
        ],
    ),
    CheckTheme(
        name="Centralize services for packages and dependencies",
        description="Checks related to using centralized services for packages and "
        "dependencies",
        checks=[
            CentralizedArtifactReposCheck(),
        ],
    ),
    CheckTheme(
        name="Deploy software programmatically",
        description="Checks related to deploying software programmatically",
        checks=[
            AutomateDeploymentsCheck(),
            ImmutableBuildsCheck(),
        ],
    ),
    CheckTheme(
        name="Regularly assess security properties of the pipelines",
        description="The pipelines you use to build and deploy your software should "
        "follow the same recommended practices as any other workload in your "
        "environment",
        checks=[
            PipelinesUseLeastPrivilegeCheck(),
            ReviewPipelinePermissionsRegularlyCheck(),
            ThreatModelPipelinesCheck(),
        ],
    ),
    CheckTheme(
        name="Build a program that embeds security ownership in workload teams",
        description="Checks related to building a program that embeds security "
        "ownership in workload teams",
        checks=[
            SecurityGuardiansProgramCheck(),
        ],
    ),
]


def all_checks():
    checks = []
    for theme in CHECK_THEMES:
        checks.extend(theme.checks)
    return checks


def find_check_by_id(check_id):
    for check in all_checks():
        if check.check_id == check_id:
            return check
    return None
