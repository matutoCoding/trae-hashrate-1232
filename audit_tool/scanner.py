import os
import re
from typing import List, Optional, Tuple

from .data_provider import DataProvider
from .models import ScanTarget, SharedItem


_LINK_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
_PATH_PATTERN = re.compile(r"^(/|\\|[a-zA-Z]:[\\/])")


def classify_target(raw: str) -> ScanTarget:
    raw = raw.strip()
    if not raw:
        return ScanTarget(raw=raw, target_type="invalid", value="")

    if _LINK_PATTERN.match(raw):
        return ScanTarget(raw=raw, target_type="link", value=raw)

    if _PATH_PATTERN.match(raw) or raw.startswith("/teams/") or raw.startswith("teams/"):
        if not raw.startswith("/") and not raw.startswith("\\"):
            raw = "/" + raw
        return ScanTarget(raw=raw, target_type="path", value=raw)

    return ScanTarget(raw=raw, target_type="unknown", value=raw)


def parse_targets_from_args(targets: List[str]) -> List[ScanTarget]:
    parsed: List[ScanTarget] = []
    for t in targets:
        if t.startswith("@"):
            file_path = t[1:]
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parsed.append(classify_target(line))
            else:
                parsed.append(ScanTarget(raw=t, target_type="file_not_found", value=file_path))
        else:
            parsed.append(classify_target(t))
    return parsed


class ScanResult:
    def __init__(self, target: ScanTarget):
        self.target = target
        self.items: List[SharedItem] = []
        self.errors: List[str] = []
        self.not_found: List[str] = []


class Scanner:
    def __init__(self, provider: DataProvider, recursive: bool = False):
        self.provider = provider
        self.recursive = recursive

    def scan(self, targets: List[ScanTarget]) -> List[ScanResult]:
        results: List[ScanResult] = []
        for target in targets:
            result = self._scan_one(target)
            results.append(result)
        return results

    def _scan_one(self, target: ScanTarget) -> ScanResult:
        result = ScanResult(target)

        if target.target_type == "invalid":
            result.errors.append("空输入")
            return result

        if target.target_type == "file_not_found":
            result.errors.append(f"目标清单文件不存在: {target.value}")
            return result

        if target.target_type == "unknown":
            result.errors.append(f"无法识别的目标类型: {target.raw}")
            return result

        if target.target_type == "link":
            item = self.provider.fetch_by_link(target.value)
            if item:
                result.items.append(item)
            else:
                result.not_found.append(target.value)
            return result

        if target.target_type == "path":
            item = self.provider.fetch_by_path(target.value)
            if item:
                result.items.append(item)
                children = self.provider.fetch_children(target.value, recursive=self.recursive)
                for child in children:
                    if child.id != item.id:
                        result.items.append(child)
            else:
                children = self.provider.fetch_children(target.value, recursive=self.recursive)
                if children:
                    result.items.extend(children)
                else:
                    result.not_found.append(target.value)
            return result

        result.errors.append(f"未处理的目标类型: {target.target_type}")
        return result
