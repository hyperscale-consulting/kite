# Kite - Cloud Security Assessments

Kite is a tool designed to help perform AWS security assessments efficiently.
It provides a suite of commands to analyze and assess security configurations
and best practices. The checks align closely with the security pillar of the
AWS Well-Architected framework.

## Installation

```bash
pip install hyperscale-kite
```

## Usage

Run the help command to get an overview of the available commands:

```bash
kite --help
```

`kite` works by assuming a role in each target account in order to check AWS
configuration. A [CloudFormation
template](https://raw.githubusercontent.com/hyperscale-consulting/kite/refs/heads/main/permissions/kite-assessment-role.yaml)
with the required permissions is available to help setting this up. This can be
deployed as a regular CloudFormation stack, or as a stack set to deploy across
multiple accounts using AWS Organizations.

### Deploying the Assessment Role

#### Single Account Deployment

To deploy the assessment role in a single account:

```bash
# Download the template
curl -O https://raw.githubusercontent.com/hyperscale-consulting/kite/refs/heads/main/permissions/kite-assessment-role.yaml

# Deploy the stack
aws cloudformation deploy \
    --template-file kite-assessment-role.yaml \
    --stack-name kite-assessment-role \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides \
        Assessor="arn:aws:sts::<ASSESSOR-ACCOUNT-ID>:assumed-role/<ROLE-NAME>/<USER>" \
        ExternalId="<EXTERNAL-ID>" \
        AssessmentEnd="2025-12-31T23:59:59Z"
```

Replace:

- `<ASSESSOR-ACCOUNT-ID>` with the AWS account ID of the assessor
- `<ROLE-NAME>` with the name of the role the assessor will use
- `<USER>` with the username or session name of the assessor
- `<EXTERNAL-ID>` with a unique identifier for this assessment
- The `AssessmentEnd` date with when the assessment should end

#### Multi-Account Deployment using Stack Sets

You can easily deploy the template across the entire AWS Organization - just
remember you need to deploy to the management account separately using the
instruction above.

To deploy the assessment role across multiple accounts using AWS Organizations:

```bash
# Download the template
curl -O https://raw.githubusercontent.com/hyperscale-consulting/kite/refs/heads/main/permissions/kite-assessment-role.yaml

# Create the stack set
aws cloudformation create-stack-set \
    --stack-set-name kite-assessment-role \
    --template-body file://kite-assessment-role.yaml \
    --capabilities CAPABILITY_NAMED_IAM \
    --permission-model service-managed \
    --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
    --parameters \
        ParameterKey=Assessor,ParameterValue="arn:aws:sts::<ASSESSOR-ACCOUNT-ID>:assumed-role/<ROLE-NAME>/<USER>" \
        ParameterKey=ExternalId,ParameterValue="<EXTERNAL-ID>" \
        ParameterKey=AssessmentEnd,ParameterValue="2025-12-31T23:59:59Z"

# Create stack instances (deploy to accounts)
aws cloudformation create-stack-instances \
    --stack-set-name kite-assessment-role \
    --accounts <ACCOUNT-ID-1> <ACCOUNT-ID-2> \
    --regions <REGION> \
    --operation-preferences FailureToleranceCount=0,MaxConcurrentCount=1

# Alternatively, deploy to all accounts in the organization
aws cloudformation create-stack-instances \
    --stack-set-name kite-assessment-role \
    --deployment-targets OrganizationalUnitIds=<OU-ID> \
    --regions <REGION> \
    --operation-preferences FailureToleranceCount=0,MaxConcurrentCount=1

# Or deploy to the entire organization (including the root)
aws cloudformation create-stack-instances \
    --stack-set-name kite-assessment-role \
    --deployment-targets OrganizationalUnitIds=r-<ROOT-ID> \
    --regions <REGION> \
    --operation-preferences FailureToleranceCount=0,MaxConcurrentCount=1
```

Replace:

- `<ASSESSOR-ACCOUNT-ID>` with the AWS account ID of the assessor
- `<ROLE-NAME>` with the name of the role the assessor will use
- `<USER>` with the username or session name of the assessor
- `<EXTERNAL-ID>` with a unique identifier for this assessment
- `<MANAGEMENT-ACCOUNT-ID>` with your AWS Organizations management account ID
- `<ACCOUNT-ID-1> <ACCOUNT-ID-2>` with the target account IDs (if using specific accounts)
- `<OU-ID>` with the ID of the organizational unit to deploy to (if using OUs)
- `<ROOT-ID>` with your organization's root ID (if deploying to entire organization)
- `<REGION>` with the AWS region to deploy to
- The `AssessmentEnd` date with when the assessment should end

Note that the above `create-stack-set` command assumes that you are using
[service-managed
permissions](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-activate-trusted-access.html).
You can also use [self-managed
permissions](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs-self-managed.html).

Once you've set up the role, you can switch to the AWS account / role from
which you will be doing the assessment. The only permission this role needs is
to be able to assume the assessment role in whichever account it is, for
example:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowAssumeKiteAssessmentRoleInAnyAccount",
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": [
                "arn:aws:iam::*:role/KiteAssessmentRole"
            ]
        }
    ]
}
```

Next, configure `kite`:

```bash
kite configure
```

`kite` can utilise the output of
[Prowler](https://github.com/prowler-cloud/prowler) checks, and the role you
created above can be used with `prowler`. If you're using AWS Organizations you
can configure `prowler` to get the most out of the `prowler` checks - take a
copy of the [config
file](https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/prowler/config/config.yaml)
and update `organizations_enabled_regions` to your enabled regions, and
`organizations_trusted_delegated_administrators` to the trusted administrator
accounts for your organization (e.g. your security tooling account).

Once installed and configured, you can run the `prowler` CLI for a standalone account:

```zsh
prowler aws \
    -R arn:aws:iam::<ACCOUNT-ID>:role/KiteAssessmentRole --external-id <EXTERNAL-ID>
```

Or for a list of accounts in an AWS Organization:

```zsh
ACCOUNT_IDS=$(kite list-accounts)
for ACCOUNT in ${(f)ACCOUNT_IDS} ; do
    prowler aws \
        -O arn:aws:iam::<MGMT-ACCOUNT-ID>:role/KiteAssessmentRole \
        -R arn:aws:iam::${ACCOUNT}:role/KiteAssessmentRole \
        --external-id <EXTERNAL-ID> \
        --config-file prowler.yaml
done
```

While `prowler` is running you can tell `kite` to collect the data it will need
for the assessment:

```bash
kite collect
```

Then, when `prowler` has finished scanning and `kite` has collected the data it
needs, you can start an assessment:

```bash
kite assess
```

## Development

### Prerequisites

- Install `uv` via the [official instructions](https://docs.astral.sh/uv/getting-started/installation/)
- Configure AWS credentials (via AWS CLI or environment variables)

### Running kite

1. Clone the repo:

```bash
git clone https://github.com/hyperscale-consulting/kite
cd kite
```

2. Run using `uv`:

```bash
uv run kite collect
uv run kite assess
```

### Running tests and linters

```bash
uv run ruff check --fix
uv run pre-commit run --all-files
uv run pytest
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
