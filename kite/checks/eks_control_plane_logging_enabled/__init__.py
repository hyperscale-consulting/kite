"""EKS control plane logging check."""

from kite.checks.eks_control_plane_logging_enabled.check import (
    check_eks_control_plane_logging_enabled,
)

__all__ = ["check_eks_control_plane_logging_enabled"]
