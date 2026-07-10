"""Load and cache Kero markdown recon skills."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict


@dataclass
class SkillLoader:
    """Recursively load markdown skills and expose a cached dictionary API."""

    skills_dir: Path
    _cache: Dict[str, str] = field(default_factory=dict)

    def load_skills(self, force_reload: bool = False) -> Dict[str, str]:
        """Load all markdown files under the skills directory."""

        if self._cache and not force_reload:
            return dict(self._cache)

        if not self.skills_dir.exists():
            return {}

        loaded: Dict[str, str] = {}
        for path in sorted(self.skills_dir.rglob("*.md")):
            stem = path.stem
            if stem.startswith("0"):
                key = stem.split("_", 1)[-1] if "_" in stem else stem
            else:
                key = stem
            loaded[key] = path.read_text(encoding="utf-8")
            loaded[path.name] = loaded[key]

        self._cache = loaded
        return dict(self._cache)

    def get_skill(self, name: str) -> str:
        """Return one skill by key or filename."""

        skills = self.load_skills()
        if name in skills:
            return skills[name]
        for key, value in skills.items():
            if Path(key).stem == name:
                return value
        raise KeyError(f"Skill not found: {name}")
