from unittest.mock import patch

from kite.checks.security_services_evaluation import check_security_services_evaluation


@patch("kite.checks.security_services_evaluation.manual_check")
def test_security_services_evaluation_pass(mock_manual_check):
    mock_manual_check.return_value = {
        "check_id": "security-services-evaluation",
        "check_name": "Security Services Evaluation",
        "status": "PASS",
        "details": {
            "message": (
                "Teams regularly evaluate and implement new security services and "
                "features."
            )
        },
    }

    result = check_security_services_evaluation()

    assert result["check_id"] == "security-services-evaluation"
    assert result["check_name"] == "Security Services Evaluation"
    assert result["status"] == "PASS"
    assert (
        "Teams regularly evaluate and implement new security services"
        in result["details"]["message"]
    )


@patch("kite.checks.security_services_evaluation.manual_check")
def test_security_services_evaluation_fail(mock_manual_check):
    mock_manual_check.return_value = {
        "check_id": "security-services-evaluation",
        "check_name": "Security Services Evaluation",
        "status": "FAIL",
        "details": {
            "message": (
                "Teams should regularly evaluate and implement new security services "
                "and features."
            )
        },
    }

    result = check_security_services_evaluation()

    assert result["check_id"] == "security-services-evaluation"
    assert result["check_name"] == "Security Services Evaluation"
    assert result["status"] == "FAIL"
    assert (
        "Teams should regularly evaluate and implement new security services"
        in result["details"]["message"]
    )
