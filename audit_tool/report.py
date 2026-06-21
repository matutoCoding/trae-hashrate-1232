from datetime import datetime
from typing import List

from .models import RuleViolation, Severity


class ReportGenerator:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self, violations: List[RuleViolation], output_path: str = None) -> str:
        report = self._build_text(violations)
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report)
        return report

    def _build_text(self, violations: List[RuleViolation]) -> str:
        lines: List[str] = []

        lines.append("=" * 70)
        lines.append("       共享文件夹权限审计报告")
        lines.append(f"       生成时间: {self.timestamp}")
        lines.append("=" * 70)
        lines.append("")

        if not violations:
            lines.append("[✓] 未发现违规权限配置。")
            lines.append("")
            return "\n".join(lines)

        high = [v for v in violations if v.severity == Severity.HIGH]
        medium = [v for v in violations if v.severity == Severity.MEDIUM]
        low = [v for v in violations if v.severity == Severity.LOW]

        lines.append(f"扫描统计: HIGH={len(high)}  MEDIUM={len(medium)}  LOW={len(low)}")
        lines.append("")
        lines.append("-" * 70)
        lines.append(" 问题清单")
        lines.append("-" * 70)

        sorted_violations = sorted(
            violations,
            key=lambda v: (
                {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[v.severity.value],
                v.item_path,
            ),
        )

        for idx, v in enumerate(sorted_violations, 1):
            severity_tag = f"[{v.severity.value}]"
            lines.append("")
            lines.append(f"{idx:>3}. {severity_tag}  {v.rule_name}  ({v.rule_id})")
            lines.append(f"     位置: {v.item_path}  ({v.item_name})")
            if v.member:
                lines.append(f"     成员: {v.member.email}  权限={v.member.permission.value}  转分享={'是' if v.member.can_reshare else '否'}")
            lines.append(f"     描述: {v.description}")
            lines.append(f"     建议: {v.suggestion}")
            lines.append(f"     复查: {v.recheck_cmd}")

        lines.append("")
        lines.append("-" * 70)
        lines.append(" 处理建议总览")
        lines.append("-" * 70)
        lines.append("")

        seen_rules = {}
        for v in sorted_violations:
            key = (v.rule_id, v.rule_name)
            if key not in seen_rules:
                seen_rules[key] = []
            seen_rules[key].append(v)

        for (rid, rname), vs in seen_rules.items():
            lines.append(f" • {rname} ({rid}) — 共 {len(vs)} 处")
            lines.append(f"   建议: {vs[0].suggestion}")
            lines.append("")

        lines.append("-" * 70)
        lines.append(" 复查命令清单")
        lines.append("-" * 70)
        lines.append("")

        seen_cmds = set()
        for v in sorted_violations:
            if v.recheck_cmd not in seen_cmds:
                lines.append(f"   {v.recheck_cmd}")
                seen_cmds.add(v.recheck_cmd)

        lines.append("")
        lines.append("=" * 70)
        lines.append("  报告结束 — 请根据上述建议登录云盘后台手动调整权限")
        lines.append("=" * 70)
        lines.append("")

        return "\n".join(lines)
