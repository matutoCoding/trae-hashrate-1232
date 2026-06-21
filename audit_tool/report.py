from datetime import datetime
from typing import List, Optional, Dict

from .models import RuleViolation, Severity
from .diff import DiffResult, ViolationDiff, ChangeType


class ReportGenerator:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(
        self,
        violations: List[RuleViolation],
        output_path: Optional[str] = None,
        ignored_violations: Optional[List[RuleViolation]] = None,
        not_found_targets: Optional[List[str]] = None,
        group_config: Optional[Dict[str, str]] = None,
    ) -> str:
        report = self._build_text(
            violations,
            ignored_violations=ignored_violations or [],
            not_found_targets=not_found_targets or [],
            group_config=group_config or {},
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
        group_config: Dict[str, str],
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

        if group_config:
            grouped = self._group_violations(violations, group_config)
            ignored_grouped = self._group_violations(ignored_violations, group_config)

            for group_name in sorted(grouped.keys()):
                g_violations = grouped[group_name]
                g_high = sum(1 for v in g_violations if v.severity == Severity.HIGH)
                g_med = sum(1 for v in g_violations if v.severity == Severity.MEDIUM)
                g_low = sum(1 for v in g_violations if v.severity == Severity.LOW)
                g_ignored = len(ignored_grouped.get(group_name, []))

                lines.append("=" * 70)
                lines.append(f" 【{group_name}】  HIGH={g_high}  MEDIUM={g_med}  LOW={g_low}  已忽略={g_ignored}")
                lines.append("=" * 70)
                self._append_violations_section(lines, g_violations)

            lines.append("=" * 70)
            lines.append(" 全局处理建议总览")
            lines.append("=" * 70)
            self._append_suggestions_section(lines, violations)
            self._append_recheck_cmds_section(lines, violations)
        else:
            lines.append("-" * 70)
            lines.append(" 问题清单")
            lines.append("-" * 70)
            self._append_violations_section(lines, violations)
            self._append_suggestions_section(lines, violations)
            self._append_recheck_cmds_section(lines, violations)

        self._append_not_found_section(lines, not_found_targets)
        self._append_ignored_section(lines, ignored_violations)

        lines.append("")
        lines.append("=" * 70)
        lines.append("  报告结束 — 请根据上述建议登录云盘后台手动调整权限")
        lines.append("=" * 70)
        lines.append("")

        return "\n".join(lines)

    def _get_group(self, path: str, groups: Dict[str, str]) -> str:
        if not groups:
            return "其他"
        for prefix, name in groups.items():
            if path.startswith(prefix):
                return name
        return "其他"

    def _group_violations(
        self, violations: List[RuleViolation], groups: Dict[str, str]
    ) -> Dict[str, List[RuleViolation]]:
        result: Dict[str, List[RuleViolation]] = {}
        for v in violations:
            group = self._get_group(v.item_path, groups)
            if group not in result:
                result[group] = []
            result[group].append(v)
        return result

    def _append_violations_section(self, lines: List[str], violations: List[RuleViolation]) -> None:
        if not violations:
            return
        lines.append("")
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

    def _append_suggestions_section(self, lines: List[str], violations: List[RuleViolation]) -> None:
        if not violations:
            return
        lines.append("")
        lines.append("-" * 70)
        lines.append(" 处理建议总览")
        lines.append("-" * 70)
        lines.append("")
        seen_rules = {}
        for v in violations:
            key = (v.rule_id, v.rule_name)
            if key not in seen_rules:
                seen_rules[key] = []
            seen_rules[key].append(v)
        for (rid, rname), vs in seen_rules.items():
            lines.append(f" • {rname} ({rid}) — 共 {len(vs)} 处")
            lines.append(f"   建议: {vs[0].suggestion}")
            lines.append("")

    def _append_recheck_cmds_section(self, lines: List[str], violations: List[RuleViolation]) -> None:
        if not violations:
            return
        lines.append("-" * 70)
        lines.append(" 复查命令清单（复制即可执行）")
        lines.append("-" * 70)
        lines.append("")
        seen_cmds = set()
        for v in violations:
            if v.recheck_cmd not in seen_cmds:
                lines.append(f"   {v.recheck_cmd}")
                seen_cmds.add(v.recheck_cmd)

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

    def generate_diff_report(
        self,
        diff_result: DiffResult,
        output_path: Optional[str] = None,
    ) -> str:
        report = self._build_diff_text(diff_result)
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report)
        return report

    def _build_diff_text(self, diff: DiffResult) -> str:
        lines: List[str] = []

        lines.append("=" * 70)
        lines.append("       共享权限巡检趋势对比报告")
        lines.append(f"       生成时间: {self.timestamp}")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"  旧扫描: {diff.old_file}  ({diff.old_generated_at})")
        lines.append(f"  新扫描: {diff.new_file}  ({diff.new_generated_at})")
        lines.append("")

        s = diff.summary
        lines.append("-" * 70)
        lines.append(" 变化汇总")
        lines.append("-" * 70)
        lines.append("")
        lines.append(f"   新增风险:   HIGH={s['new']['HIGH']}  MEDIUM={s['new']['MEDIUM']}  LOW={s['new']['LOW']}  TOTAL={s['new']['TOTAL']}")
        lines.append(f"   已修复:     HIGH={s['fixed']['HIGH']}  MEDIUM={s['fixed']['MEDIUM']}  LOW={s['fixed']['LOW']}  TOTAL={s['fixed']['TOTAL']}")
        lines.append(f"   仍存在:     HIGH={s['existing']['HIGH']}  MEDIUM={s['existing']['MEDIUM']}  LOW={s['existing']['LOW']}  TOTAL={s['existing']['TOTAL']}")
        lines.append("")

        if diff.new_violations:
            self._append_diff_section(lines, diff.new_violations, ChangeType.NEW)

        if diff.fixed_violations:
            self._append_diff_section(lines, diff.fixed_violations, ChangeType.FIXED)

        if diff.existing_violations:
            self._append_diff_section(lines, diff.existing_violations, ChangeType.EXISTING)

        lines.append("")
        lines.append("=" * 70)
        lines.append("  报告结束 — 请重点关注新增风险并确认已修复项")
        lines.append("=" * 70)
        lines.append("")

        return "\n".join(lines)

    def _append_diff_section(self, lines: List[str], violations: List[ViolationDiff], change_type: ChangeType) -> None:
        section_titles = {
            ChangeType.NEW: ("新增风险", "+", "32"),
            ChangeType.FIXED: ("已修复", "-", "36"),
            ChangeType.EXISTING: ("仍存在", "•", "33"),
        }
        title, bullet, _ = section_titles[change_type]
        count = len(violations)

        lines.append("-" * 70)
        lines.append(f" {title}（{count} 条）")
        lines.append("-" * 70)
        lines.append("")

        sorted_vs = sorted(
            violations,
            key=lambda v: (
                {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[v.severity.value],
                v.item_path,
            ),
        )

        for idx, v in enumerate(sorted_vs, 1):
            lines.append(f" {bullet:>2} {idx:>3}. [{v.severity.value}] {v.rule_name}  ({v.rule_id})")
            lines.append(f"        位置: {v.item_path}  ({v.item_name})")
            lines.append(f"        成员: {v.member_email}")
            if change_type == ChangeType.NEW and v.new_description:
                lines.append(f"        描述: {v.new_description}")
            elif change_type == ChangeType.FIXED and v.old_description:
                lines.append(f"        原描述: {v.old_description}")
            elif change_type == ChangeType.EXISTING:
                if v.new_description:
                    lines.append(f"        描述: {v.new_description}")
            lines.append("")
