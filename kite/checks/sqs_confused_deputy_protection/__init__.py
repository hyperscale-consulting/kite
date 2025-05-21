"""SQS confused deputy protection check package."""

from kite.checks.sqs_confused_deputy_protection.check import check_sqs_confused_deputy_protection

__all__ = ["check_sqs_confused_deputy_protection"]
