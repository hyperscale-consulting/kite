from botocore.exceptions import ClientError

from hyperscale.kite.models import Account
from hyperscale.kite.models import ControlPolicy
from hyperscale.kite.models import DelegatedAdmin
from hyperscale.kite.models import Organization
from hyperscale.kite.models import OrganizationalUnit


def _fetch_policies_for_target(
    orgs_client, target_id: str
) -> dict[str, list[ControlPolicy]]:
    """
    Fetch all SCPs and RCPs attached to a target (account or OU).

    Args:
        orgs_client: The boto3 organizations client
        target_id: The ID of the target (account or OU)

    Returns:
        A dictionary containing lists of ControlPolicy objects for each policy type
    """
    policies = {
        "SERVICE_CONTROL_POLICY": [],
        "RESOURCE_CONTROL_POLICY": [],
        "TAG_POLICY": [],
    }

    for policy_type in policies.keys():
        paginator = orgs_client.get_paginator("list_policies_for_target")
        for page in paginator.paginate(TargetId=target_id, Filter=policy_type):
            for policy in page["Policies"]:
                # Get the policy details
                policy_response = orgs_client.describe_policy(PolicyId=policy["Id"])
                policy_details = policy_response["Policy"]
                policy_summary = policy_details["PolicySummary"]

                pol = ControlPolicy(
                    id=policy_summary["Id"],
                    arn=policy_summary["Arn"],
                    name=policy_summary["Name"],
                    description=policy_summary.get("Description", ""),
                    content=policy_details["Content"],
                    type=policy_summary["Type"],
                )

                policies[policy_summary["Type"]].append(pol)

    return policies


def fetch_organization(session) -> Organization:
    """
    Describe the AWS organization structure.

    Args:
        session: A boto3 session to use for AWS API calls

    Returns:
        An Organization object containing the structure of the AWS organization,
        or None if AWS Organizations is not in use.
    """
    orgs_client = session.client("organizations")

    # Get organization details
    org_response = orgs_client.describe_organization()
    org = org_response["Organization"]

    # Get root ID
    roots_response = orgs_client.list_roots()
    root = roots_response["Roots"][0]
    root_id = root["Id"]
    root_arn = root["Arn"]
    root_name = root.get("Name", "Root")

    # Get policies for the root
    root_policies = _fetch_policies_for_target(orgs_client, root_id)

    # Get accounts in the root
    accounts = []
    paginator = orgs_client.get_paginator("list_accounts_for_parent")
    for page in paginator.paginate(ParentId=root_id):
        for account in page["Accounts"]:
            # Get policies for this account
            account_policies = _fetch_policies_for_target(orgs_client, account["Id"])

            accounts.append(
                Account(
                    id=account["Id"],
                    arn=account["Arn"],
                    name=account["Name"],
                    email=account["Email"],
                    status=account["Status"],
                    joined_method=account["JoinedMethod"],
                    joined_timestamp=account["JoinedTimestamp"].isoformat(),
                    scps=account_policies["SERVICE_CONTROL_POLICY"],
                    rcps=account_policies["RESOURCE_CONTROL_POLICY"],
                    tag_policies=account_policies["TAG_POLICY"],
                )
            )

    # Get child OUs
    child_ous = []
    paginator = orgs_client.get_paginator("list_children")
    for page in paginator.paginate(ParentId=root_id, ChildType="ORGANIZATIONAL_UNIT"):
        for child in page["Children"]:
            child_ous.append(build_ou_structure(orgs_client, child["Id"]))

    # Create the root OU
    root_ou = OrganizationalUnit(
        id=root_id,
        arn=root_arn,
        name=root_name,
        accounts=accounts,
        child_ous=child_ous,
        scps=root_policies["SERVICE_CONTROL_POLICY"],
        rcps=root_policies["RESOURCE_CONTROL_POLICY"],
        tag_policies=root_policies["TAG_POLICY"],
    )

    return Organization(
        id=org["Id"],
        master_account_id=org["MasterAccountId"],
        arn=org["Arn"],
        feature_set=org["FeatureSet"],
        root=root_ou,
    )


def build_ou_structure(orgs_client, ou_id):
    """Recursively build the OU structure."""
    # Get OU details
    ou_response = orgs_client.describe_organizational_unit(OrganizationalUnitId=ou_id)
    ou = ou_response["OrganizationalUnit"]

    # Get policies for this OU
    ou_policies = _fetch_policies_for_target(orgs_client, ou_id)

    # Get accounts in this OU
    accounts = []
    paginator = orgs_client.get_paginator("list_accounts_for_parent")
    for page in paginator.paginate(ParentId=ou_id):
        for account in page["Accounts"]:
            # Get policies for this account
            account_policies = _fetch_policies_for_target(orgs_client, account["Id"])

            accounts.append(
                Account(
                    id=account["Id"],
                    arn=account["Arn"],
                    name=account["Name"],
                    email=account["Email"],
                    status=account["Status"],
                    joined_method=account["JoinedMethod"],
                    joined_timestamp=account["JoinedTimestamp"].isoformat(),
                    scps=account_policies["SERVICE_CONTROL_POLICY"],
                    rcps=account_policies["RESOURCE_CONTROL_POLICY"],
                    tag_policies=account_policies["TAG_POLICY"],
                )
            )

    # Get child OUs
    child_ous = []
    paginator = orgs_client.get_paginator("list_children")
    for page in paginator.paginate(ParentId=ou_id, ChildType="ORGANIZATIONAL_UNIT"):
        for child in page["Children"]:
            child_ous.append(build_ou_structure(orgs_client, child["Id"]))

    return OrganizationalUnit(
        id=ou["Id"],
        arn=ou["Arn"],
        name=ou["Name"],
        accounts=accounts,
        child_ous=child_ous,
        scps=ou_policies["SERVICE_CONTROL_POLICY"],
        rcps=ou_policies["RESOURCE_CONTROL_POLICY"],
        tag_policies=ou_policies["TAG_POLICY"],
    )


def fetch_delegated_admins(session) -> list[DelegatedAdmin]:
    """
    Fetch all delegated administrators for the organization.

    This function retrieves information about accounts that have been delegated
    administrative privileges for any AWS service within the organization.

    Args:
        session: A boto3 session to use for AWS API calls

    Returns:
        A list of DelegatedAdmin objects.

    """
    orgs_client = session.client("organizations")
    delegated_admins = []

    try:
        # List all delegated administrators
        paginator = orgs_client.get_paginator("list_delegated_administrators")

        for page in paginator.paginate():
            for admin in page["DelegatedAdministrators"]:
                # Get additional details about the account
                account_details = orgs_client.describe_account(AccountId=admin["Id"])[
                    "Account"
                ]

                # Get the list of services this account is delegated for
                services_paginator = orgs_client.get_paginator(
                    "list_delegated_services_for_account"
                )
                for services_page in services_paginator.paginate(AccountId=admin["Id"]):
                    for service in services_page["DelegatedServices"]:
                        service_principal = service["ServicePrincipal"]

                        joined_timestamp = account_details["JoinedTimestamp"]
                        delegation_date = service["DelegationEnabledDate"]
                        delegated_admins.append(
                            DelegatedAdmin(
                                id=admin["Id"],
                                arn=admin["Arn"],
                                email=account_details["Email"],
                                name=account_details["Name"],
                                status=account_details["Status"],
                                joined_method=account_details["JoinedMethod"],
                                joined_timestamp=joined_timestamp.isoformat(),
                                delegation_enabled_date=delegation_date.isoformat(),
                                service_principal=service_principal,
                            )
                        )

        return delegated_admins
    except ClientError as e:
        if e.response["Error"]["Code"] == "AWSOrganizationsNotInUseException":
            return []

        # Re-raise other exceptions
        raise


def get_account_details(session, account_id: str) -> Account | None:
    """
    Fetch details for a specific account in the organization.

    Args:
        session: A boto3 session to use for AWS API calls
        account_id: The ID of the account to fetch details for

    Returns:
        An Account object containing the account details, or None if the account is not
        found
    """
    orgs_client = session.client("organizations")

    try:
        # Get account details
        account_response = orgs_client.describe_account(AccountId=account_id)
        account = account_response["Account"]

        # Get policies for this account
        account_policies = _fetch_policies_for_target(orgs_client, account_id)

        return Account(
            id=account["Id"],
            arn=account["Arn"],
            name=account["Name"],
            email=account["Email"],
            status=account["Status"],
            joined_method=account["JoinedMethod"],
            joined_timestamp=account["JoinedTimestamp"].isoformat(),
            scps=account_policies["SERVICE_CONTROL_POLICY"],
            rcps=account_policies["RESOURCE_CONTROL_POLICY"],
            tag_policies=account_policies["TAG_POLICY"],
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccountNotFoundException":
            return None
        # Re-raise other exceptions
        raise


def fetch_account_ids(session) -> list[str]:
    """
    Fetch all account IDs in the organization.

    Args:
        session: A boto3 session to use for AWS API calls

    Returns:
        A list of account IDs in the organization
    """
    orgs_client = session.client("organizations")

    account_ids = []
    paginator = orgs_client.get_paginator("list_accounts")
    for page in paginator.paginate():
        for account in page["Accounts"]:
            account_ids.append(account["Id"])
    return account_ids
