from dataclasses import asdict

import pytest

from hyperscale.kite.core import Assessment
from hyperscale.kite.core import Finding


@pytest.fixture
def assessment():
    assessment = Assessment()
    assessment.record(
        "theme1",
        "practice1",
        Finding(
            check_id="check1",
            check_name="check1",
            status="PASS",
            criticality=10,
            difficulty=10,
            reason="",
            description="Check 1",
            details={},
        ),
    )
    assessment.record(
        "theme1",
        "practice1",
        Finding(
            check_id="check2",
            check_name="check2",
            status="FAIL",
            criticality=5,
            difficulty=5,
            reason="",
            description="Check 2",
            details={},
        ),
    )
    assessment.record(
        "theme1",
        "practice1",
        Finding(
            check_id="check3",
            check_name="check3",
            status="PASS",
            criticality=3,
            difficulty=1,
            reason="",
            description="Check 3",
            details={},
        ),
    )
    assessment.record(
        "theme1",
        "practice2",
        Finding(
            check_id="check4",
            check_name="check4",
            status="PASS",
            criticality=5,
            difficulty=1,
            reason="",
            description="Check 4",
            details={},
        ),
    )
    assessment.record(
        "theme1",
        "practice2",
        Finding(
            check_id="check5",
            check_name="check5",
            status="FAIL",
            criticality=5,
            difficulty=4,
            reason="",
            description="Check 5",
            details={},
        ),
    )
    assessment.record(
        "theme2",
        "practice3",
        Finding(
            check_id="check6",
            check_name="check6",
            status="FAIL",
            criticality=10,
            difficulty=2,
            reason="",
            description="Check 6",
            details={},
        ),
    )
    assessment.record(
        "theme2",
        "practice3",
        Finding(
            check_id="check7",
            check_name="check7",
            status="FAIL",
            criticality=1,
            difficulty=2,
            reason="",
            description="Check 7",
            details={},
        ),
    )
    return assessment


def test_assessment_score(assessment):
    results = asdict(assessment)
    assert results["score_raw"] == 18
    assert results["score_max"] == 39
    assert results["score_percentage"] == 46


def test_assessment_priorities(assessment):
    results = asdict(assessment)
    assert results["priorities"] == [
        dict(
            check_id="check6",
            check_name="check6",
            criticality=10,
            difficulty=2,
            description="Check 6",
        ),
        dict(
            check_id="check5",
            check_name="check5",
            criticality=5,
            difficulty=4,
            description="Check 5",
        ),
        dict(
            check_id="check2",
            check_name="check2",
            criticality=5,
            difficulty=5,
            description="Check 2",
        ),
        dict(
            check_id="check7",
            check_name="check7",
            criticality=1,
            difficulty=2,
            description="Check 7",
        ),
    ]
