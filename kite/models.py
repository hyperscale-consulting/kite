"""Data models for Kite."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, UTC


@dataclass
class ServiceControlPolicy:
    """Represents a Service Control Policy in the organization."""

    id: str
    arn: str
    name: str
    description: str
    content: str
    type: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceControlPolicy":
        """Create a ServiceControlPolicy from a dictionary."""
        return cls(**data)


@dataclass
class Account:
    """Represents an AWS account within an organization."""

    id: str
    arn: str
    name: str
    email: str
    status: str
    joined_method: str
    joined_timestamp: str
    scps: List[ServiceControlPolicy]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Account":
        """Create an Account from a dictionary."""
        scps = [ServiceControlPolicy.from_dict(scp) for scp in data.pop('scps', [])]
        return cls(**data, scps=scps)


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
    def from_dict(cls, data: Dict[str, Any]) -> "DelegatedAdmin":
        """Create a DelegatedAdmin from a dictionary."""
        return cls(**data)


@dataclass
class OrganizationalUnit:
    """Represents an organizational unit within an organization."""

    id: str
    arn: str
    name: str
    accounts: List[Account]
    child_ous: List["OrganizationalUnit"]
    scps: List[ServiceControlPolicy]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OrganizationalUnit":
        """Create an OrganizationalUnit from a dictionary."""
        accounts = [Account.from_dict(acc) for acc in data.pop('accounts', [])]
        child_ous = [cls.from_dict(ou) for ou in data.pop('child_ous', [])]
        scps = [ServiceControlPolicy.from_dict(scp) for scp in data.pop('scps', [])]
        return cls(**data, accounts=accounts, child_ous=child_ous, scps=scps)

    def get_accounts(self) -> List[Account]:
        """Get all accounts in the organizational unit and its child organizational units."""
        accounts = self.accounts
        for child_ou in self.child_ous:
            accounts.extend(child_ou.get_accounts())
        return accounts


@dataclass
class Organization:
    """Represents an AWS organization with its structure."""

    master_account_id: str
    arn: str
    feature_set: str
    root: OrganizationalUnit

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Organization":
        """Create an Organization from a dictionary."""
        root = OrganizationalUnit.from_dict(data.pop('root'))
        return cls(**data, root=root)

    def get_accounts(self) -> List[Account]:
        """Get all accounts in the organization."""
        return self.root.get_accounts()


@dataclass
class WorkloadResource:
    """Base class for workload resources."""

    resource_type: str
    resource_id: str
    region: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkloadResources:
    """Collection of workload resources."""

    resources: List[WorkloadResource] = field(default_factory=list)
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> Dict[str, Any]:
        """Convert the model to a dictionary."""
        return {
            "resources": [
                {
                    "resource_type": r.resource_type,
                    "resource_id": r.resource_id,
                    "region": r.region,
                    "details": r.details,
                }
                for r in self.resources
            ],
            "collected_at": self.collected_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WorkloadResources":
        """Create a model from a dictionary."""
        return cls(
            resources=[
                WorkloadResource(
                    resource_type=r["resource_type"],
                    resource_id=r["resource_id"],
                    region=r.get("region"),
                    details=r.get("details", {}),
                )
                for r in data.get("resources", [])
            ],
            collected_at=datetime.fromisoformat(
                data.get("collected_at", datetime.now(UTC).isoformat())
            ),
        )
