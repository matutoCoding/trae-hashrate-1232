import json
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from enum import Enum

from .models import Severity


class ChangeType(Enum):
    NEW = "new"
    FIXED = "fixed"
    EXISTING = "existing"


@dataclass
class ViolationDiff:
    rule_id: str
    rule_name: str
    severity: Severity
    item_path: str
    item_name: str
    member_email: str
    change_type: ChangeType
    old_description: Optional[str] = None
    new_description: Optional[str] = None


@dataclass
class DiffResult:
    old_file: str
    new_file: str
    old_generated_at: str = ""
    new_generated_at: str = ""
    new_violations: List[ViolationDiff] = field(default_factory=list)
    fixed_violations: List[ViolationDiff] = field(default_factory=list)
    existing_violations: List[ViolationDiff] = field(default_factory=list)

    @property
    def summary(self) -> Dict[str, Dict[str, int]]:
        result = {
            "new": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "TOTAL": 0},
            "fixed": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "TOTAL": 0},
            "existing": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "TOTAL": 0},
        }
        for v in self.new_violations:
            result["new"][v.severity.value] += 1
            result["new"]["TOTAL"] += 1
        for v in self.fixed_violations:
            result["fixed"][v.severity.value] += 1
            result["fixed"]["TOTAL"] += 1
        for v in self.existing_violations:
            result["existing"][v.severity.value] += 1
            result["existing"]["TOTAL"] += 1
        return result


def _violation_key(v: dict) -> Tuple[str, str, str]:
    return (v.get("item_path", ""), v.get("member_email", ""), v.get("rule_id", ""))


def _build_violation_diff(
    v: dict, change_type: ChangeType, old_desc: Optional[str] = None, new_desc: Optional[str] = None
) -> ViolationDiff:
    return ViolationDiff(
        rule_id=v.get("rule_id", ""),
        rule_name=v.get("rule_name", ""),
        severity=Severity(v.get("severity", "MEDIUM")),
        item_path=v.get("item_path", ""),
        item_name=v.get("item_name", ""),
        member_email=v.get("member_email", ""),
        change_type=change_type,
        old_description=old_desc,
        new_description=new_desc,
    )


def compare_json_files(old_path: str, new_path: str, severity_filter: Optional[List[str]] = None) -> DiffResult:
    with open(old_path, "r", encoding="utf-8") as f:
        old_data = json.load(f)
    with open(new_path, "r", encoding="utf-8") as f:
        new_data = json.load(f)

    old_violations = old_data.get("violations", []) + old_data.get("ignored_violations", [])
    new_violations = new_data.get("violations", []) + new_data.get("ignored_violations", [])

    if severity_filter:
        old_violations = [v for v in old_violations if v.get("severity", "") in severity_filter]
        new_violations = [v for v in new_violations if v.get("severity", "") in severity_filter]

    old_map: Dict[Tuple[str, str, str], dict] = {_violation_key(v): v for v in old_violations}
    new_map: Dict[Tuple[str, str, str], dict] = {_violation_key(v): v for v in new_violations}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    result = DiffResult(
        old_file=old_path,
        new_file=new_path,
        old_generated_at=old_data.get("generated_at", ""),
        new_generated_at=new_data.get("generated_at", ""),
    )

    for key in new_keys - old_keys:
        v = new_map[key]
        result.new_violations.append(_build_violation_diff(v, ChangeType.NEW, new_desc=v.get("description", "")))

    for key in old_keys - new_keys:
        v = old_map[key]
        result.fixed_violations.append(_build_violation_diff(v, ChangeType.FIXED, old_desc=v.get("description", "")))

    for key in old_keys & new_keys:
        old_v = old_map[key]
        new_v = new_map[key]
        result.existing_violations.append(
            _build_violation_diff(
                new_v,
                ChangeType.EXISTING,
                old_desc=old_v.get("description", ""),
                new_desc=new_v.get("description", ""),
            )
        )

    return result
