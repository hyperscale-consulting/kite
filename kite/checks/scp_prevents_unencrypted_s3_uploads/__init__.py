"""SCP prevents unencrypted S3 uploads check."""

from .check import check_scp_prevents_unencrypted_s3_uploads

__all__ = ["check_scp_prevents_unencrypted_s3_uploads"]
