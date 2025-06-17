"""SSL cipher security check."""

from kite.checks.avoid_insecure_ssl_ciphers.check import (
    check_avoid_insecure_ssl_ciphers,
)

__all__ = ["check_avoid_insecure_ssl_ciphers"]
