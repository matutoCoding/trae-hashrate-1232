from datetime import datetime
from typing import List, Optional

from .models import RuleViolation, Severity


class ReportGenerator:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(
        self,
        violations: List[RuleViolation],
        output_path: Optional[str] = None,
        ignored_violations: Optional[List[RuleViolation]] = None,
        not_found_targets: Optional[List[str]] = None,
    ) -> str:
        report = self._build_text(
            violations,
            ignored_violations=ignored_violations or [],
            not_found_targets=not_found_targets or [],
        )
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report)
        return report

    def _build_text(
        self,
        violations: List[RuleViolation],
        ignored_violations: List[RuleViolation],
        not_found_targets: List[str],
    ) -> str:
        lines: List[str] = []

        lines.append("=" * 70)
        lines.append("       共享文件夹权限审计报告")
        lines.append(f"       生成时间: {self.timestamp}")
        lines.append("=" * 70)
        lines.append("")

        if not_found_targets:
            lines.append(f"未找到目标: {len(not_found_targets)} 个（详见末尾）")
            lines.append("")

        if ignored_violations:
            lines.append(f"基线白名单已忽略: {len(ignored_violations)} 条（详见末尾）")
            lines.append("")

        if not violations:
            lines.append("[✓] 未发现违规权限配置。")
            lines.append("")
            self._append_not_found_section(lines, not_found_targets)
            self._append_ignored_section(lines, ignored_violations)
            lines.append("=" * 70)
            lines.append("  报告结束 — 请根据上述建议登录云盘后台手动调整权限")
            lines.append("=" * 70)
            lines.append("")
            return "\n".join(lines)

        high = [v for v in violations if v.severity == Severity.HIGH]
        medium = [v for v in violations if v.severity == Severity.MEDIUM]
        low = [v for v in violations if v.severity == Severity.LOW]

        lines.append(f"扫描统计: HIGH={len(high)}  MEDIUM={len(medium)}  LOW={len(low)}  已忽略={len(ignored_violations)}")
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
        lines.append(" 复查命令清单（复制即可执行）")
        lines.append("-" * 70)
        lines.append("")

        seen_cmds = set()
        for v in sorted_violations:
            if v.recheck_cmd not in seen_cmds:
                lines.append(f"   {v.recheck_cmd}")
                seen_cmds.add(v.recheck_cmd)

        self._append_not_found_section(lines, not_found_targets)
        self._append_ignored_section(lines, ignored_violations)

        lines.append("")
        lines.append("=" * 70)
        lines.append("  报告结束 — 请根据上述建议登录云盘后台手动调整权限")
        lines.append("=" * 70)
        lines.append("")

        return "\n".join(lines)

    def _append_not_found_section(self, lines: List[str], not_found: List[str]) -> None:
        if not not_found:
            return
        lines.append("")
        lines.append("-" * 70)
        lines.append(f" 未找到目标（{len(not_found)} 个）")
        lines.append("-" * 70)
        lines.append("")
        for nf in not_found:
            lines.append(f"   • {nf}")
        lines.append("")
        lines.append("   建议：核对路径/链接拼写是否正确，或重新导出数据源。")

    def _append_ignored_section(self, lines: List[str], ignored: List[RuleViolation]) -> None:
        if not ignored:
            return
        lines.append("")
        lines.append("-" * 70)
        lines.append(f" 基线白名单已忽略（{len(ignored)} 条）")
        lines.append("-" * 70)
        lines.append("")

        seen = set()
        for v in ignored:
            key = f"{v.rule_id}:{v.item_path}:{v.member.email if v.member else ''}"
            if key in seen:
                continue
            seen.add(key)
            member_info = f" | 成员: {v.member.email}" if v.member else ""
            lines.append(f"   • [{v.severity.value}] {v.rule_name} | {v.item_path}{member_info}")
        lines.append("")
        lines.append("   说明：以上条目已在白名单中批准，本次扫描暂不处理。")
