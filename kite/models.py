from dataclasses import dataclass
from dataclasses import field
from typing import Any


@dataclass
class ControlPolicy:
    """Represents a Service Control Policy (SCP) or Resource Control Policy (RCP) in the
    organization."""

    id: str
    arn: str
    name: str
    description: str
    content: str
    type: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ControlPolicy":
        """Create a ControlPolicy from a dictionary."""
        return cls(**data)


@dataclass
class Account:
    """AWS account information."""

    id: str
    arn: str
    name: str
    email: str
    status: str
    joined_method: str
    joined_timestamp: str
    scps: list[ControlPolicy]
    rcps: list[ControlPolicy] = field(default_factory=list)
    tag_policies: list[ControlPolicy] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Account":
        """Create an Account from a dictionary."""
        scps = [ControlPolicy.from_dict(scp) for scp in data.pop("scps", [])]
        rcps = [ControlPolicy.from_dict(rcp) for rcp in data.pop("rcps", [])]
        tag_policies = [
            ControlPolicy.from_dict(tag_policies)
            for tag_policies in data.pop("tag_policies", [])
        ]
        return cls(**data, scps=scps, rcps=rcps, tag_policies=tag_policies)


@dataclass
class EC2Instance:
    """EC2 instance data class."""

    instance_id: str
    instance_type: str
    state: str
    region: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EC2Instance":
        """Create an EC2Instance from a dictionary."""
        return cls(**data)


@dataclass
class DelegatedAdmin:
    """Represents a delegated administrator in the organization."""

    id: str
    arn: str
    email: str
    name: str
    status: str
    joined_method: str
    joined_timestamp: str
    delegation_enabled_date: str
    service_principal: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DelegatedAdmin":
        """Create a DelegatedAdmin from a dictionary."""
        return cls(**data)


@dataclass
class OrganizationalUnit:
    """AWS organizational unit information."""

    id: str
    arn: str
    name: str
    accounts: list[Account]
    child_ous: list["OrganizationalUnit"]
    scps: list[ControlPolicy]
    rcps: list[ControlPolicy] = field(default_factory=list)
    tag_policies: list[ControlPolicy] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OrganizationalUnit":
        accounts = [Account.from_dict(acc) for acc in data.pop("accounts", [])]
        child_ous = [cls.from_dict(ou) for ou in data.pop("child_ous", [])]
        scps = [ControlPolicy.from_dict(scp) for scp in data.pop("scps", [])]
        rcps = [ControlPolicy.from_dict(rcp) for rcp in data.pop("rcps", [])]
        tag_policies = [
            ControlPolicy.from_dict(tag_policies)
            for tag_policies in data.pop("tag_policies", [])
        ]
        return cls(
            **data,
            accounts=accounts,
            child_ous=child_ous,
            scps=scps,
            rcps=rcps,
            tag_policies=tag_policies,
        )

    def get_accounts(self) -> list[Account]:
        accounts = self.accounts
        for child_ou in self.child_ous:
            accounts.extend(child_ou.get_accounts())
        return accounts


@dataclass
class Organization:
    """Represents an AWS organization with its structure."""

    id: str
    master_account_id: str
    arn: str
    feature_set: str
    root: OrganizationalUnit

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Organization":
        root = OrganizationalUnit.from_dict(data.pop("root"))
        return cls(**data, root=root)

    def get_accounts(self) -> list[Account]:
        return self.root.get_accounts()
