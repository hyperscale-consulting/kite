from collections import defaultdict
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime

import yaml


@dataclass
class Assessment:
    timestamp: str = datetime.now().isoformat()
    config_file: str = "kite.yaml"
    themes: dict = field(default_factory=lambda: defaultdict(list))

    @classmethod
    def load(cls) -> "Assessment":
        with open("kite-results.yaml") as f:
            data = yaml.safe_load(f)
            data["themes"] = defaultdict(list, data.get("themes", {}))
            return Assessment(**data)

    def record(self, theme_name: str, finding):
        self.themes[theme_name].append(finding)

    def save(self):
        with open("kite-results.yaml", "w") as f:
            data = asdict(self)
            data["themes"] = dict(
                self.themes
            )  # Convert defaultdict to dict for YAML serialization
            yaml.dump(data, f, default_flow_style=False)

    def has_finding(self, check_id: str) -> bool:
        return self._get_finding(check_id) is not None

    def _get_finding(self, check_id: str) -> dict | None:
        for _, findings in self.themes.items():
            for f in findings:
                if f["check_id"] == check_id:
                    return f
        return None

    def get_finding(self, check_id: str) -> dict:
        finding = self._get_finding(check_id)
        if finding is None:
            raise ValueError(f"No finding found for check ID: {check_id}")
        return finding
