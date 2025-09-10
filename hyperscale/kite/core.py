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


@dataclass
class ThemeAssessment:
    practices: dict[str, PracticeAssessment] = field(default_factory=dict)

    def record(self, practice: str, finding: Finding):
        self.practices.setdefault(practice, PracticeAssessment()).findings.append(
            finding
        )


@dataclass
class Assessment:
    timestamp: str = datetime.now().isoformat()
    config_file: str = "kite.yaml"
    themes: dict[str, ThemeAssessment] = field(default_factory=dict)

    @classmethod
    def load(cls) -> "Assessment":
        with open("kite-results.yaml") as f:
            data = yaml.safe_load(f)
            return from_dict(Assessment, data)

    def record(self, theme: str, practice: str, finding: Finding):
        self.themes.setdefault(theme, ThemeAssessment()).record(practice, finding)

    def save(self):
        with open("kite-results.yaml", "w") as f:
            yaml.safe_dump(asdict(self), f, sort_keys=False)

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
