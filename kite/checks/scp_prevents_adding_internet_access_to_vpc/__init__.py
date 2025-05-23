"""SCP prevents adding internet access to VPC check module."""

from kite.checks.scp_prevents_adding_internet_access_to_vpc.check import (
    check_scp_prevents_adding_internet_access_to_vpc,
)

__all__ = ["check_scp_prevents_adding_internet_access_to_vpc"]
