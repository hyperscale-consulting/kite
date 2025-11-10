from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime

import yaml
from dacite import from_dict


@dataclass
class Finding:
    check_id: str
    check_name: str
    status: str
    description: str
    criticality: int
    difficulty: int
    reason: str
    details: dict = field(default_factory=dict)


def make_finding(
    check_id: str,
    check_name: str,
    criticality: int,
    difficulty: int,
    status: str,
    reason: str,
    description: str,
    details: dict | None = None,
) -> Finding:
    details = details or {}
    details["message"] = reason  # backward compatibility with legacy checks
    return Finding(
        check_id=check_id,
        check_name=check_name,
        status=status,
        description=description,
        criticality=criticality,
        difficulty=difficulty,
        reason=reason,
        details=details,
    )


@dataclass
class PracticeAssessment:
    findings: list[Finding] = field(default_factory=list)
    score_raw: int = 0
    score_max: int = 0
    score_percentage: int = 0

    def _find_finding(self, check_id: str) -> Finding | None:
        for finding in self.findings:
            if finding.check_id == check_id:
                return finding

    def record(self, finding: Finding):
        existing = self._find_finding(finding.check_id)
        if existing:
            existing.status = finding.status
            existing.reason = finding.reason
            existing.details = finding.details
            existing.criticality = finding.criticality
        else:
            self.findings.append(finding)

        self.score_raw = self.score()
        self.score_max = self.max_score()
        self.score_percentage = (
            self.score_raw * 100 // self.score_max if self.score_max > 0 else 0
        )

    def max_score(self) -> int:
        return sum([f.criticality for f in self.findings])

    def score(self) -> int:
        return sum([f.criticality for f in self.findings if f.status == "PASS"])

    def failures(self) -> list[Finding]:
        return [f for f in self.findings if f.status == "FAIL"]


@dataclass
class ThemeAssessment:
    practices: dict[str, PracticeAssessment] = field(default_factory=dict)
    score_raw: int = 0
    score_max: int = 0
    score_percentage: int = 0

    def record(self, practice: str, finding: Finding):
        self.practices.setdefault(practice, PracticeAssessment()).record(finding)
        self.score_raw = self.score()
        self.score_max = self.max_score()
        self.score_percentage = (
            self.score_raw * 100 // self.score_max if self.score_max > 0 else 0
        )

    def max_score(self) -> int:
        return sum([p.max_score() for p in self.practices.values()])

    def score(self) -> int:
        return sum([p.score() for p in self.practices.values()])

    def failures(self) -> list[Finding]:
        return [
            finding
            for practice in self.practices.values()
            for finding in practice.failures()
        ]


@dataclass
class Assessment:
    timestamp: str = datetime.now().isoformat()
    config_file: str = "kite.yaml"
    themes: dict[str, ThemeAssessment] = field(default_factory=dict)
    priorities: list[dict] = field(default_factory=list)
    score_raw: int = 0
    score_max: int = 0
    score_percentage: int = 0

    @classmethod
    def load(cls) -> "Assessment":
        with open("kite-results.yaml") as f:
            data = yaml.safe_load(f)
            return from_dict(Assessment, data)

    def record(self, theme: str, practice: str, finding: Finding):
        self.themes.setdefault(theme, ThemeAssessment()).record(practice, finding)
        self.score_raw = self.score()
        self.score_max = self.max_score()
        self.score_percentage = (
            self.score_raw * 100 // self.score_max if self.score_max > 0 else 0
        )
        self.priorities = self._priorities()

    def save(self):
        with open("kite-results.yaml", "w") as f:
            yaml.safe_dump(asdict(self), f, sort_keys=False)

    def _priorities(self) -> list[dict]:
        failed_findings = sorted(
            [finding for theme in self.themes.values() for finding in theme.failures()],
            key=lambda x: (-x.criticality, x.difficulty),
        )
        return [
            dict(
                check_id=f.check_id,
                check_name=f.check_name,
                description=f.description,
                criticality=f.criticality,
                difficulty=f.difficulty,
            )
            for f in failed_findings
        ]

    def score(self) -> int:
        return sum([theme.score() for theme in self.themes.values()])

    def max_score(self) -> int:
        return sum([theme.max_score() for theme in self.themes.values()])

    def has_finding(self, check_id: str) -> bool:
        return self._get_finding(check_id) is not None

    def _get_finding(self, check_id: str) -> Finding | None:
        for _, theme in self.themes.items():
            for _, practice in theme.practices.items():
                for f in practice.findings:
                    if f.check_id == check_id:
                        return f

        return None

    def get_finding(self, check_id: str) -> Finding:
        finding = self._get_finding(check_id)
        if finding is None:
            raise ValueError(f"No finding found for check ID: {check_id}")
        return finding
