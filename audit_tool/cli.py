import argparse
import csv
import json
import os
import sys
from datetime import datetime
from typing import List, Optional

from colorama import Fore, Style, init as colorama_init
from tabulate import tabulate

from .data_provider import DataProvider, MockDataProvider, FileDataProvider
from .models import (
    Member,
    MemberType,
    PermissionLevel,
    RuleViolation,
    ScanTarget,
    Severity,
    SharedItem,
)
from .report import ReportGenerator
from .rules import RuleEngine
from .scanner import Scanner, parse_targets_from_args


def _init_colorama():
    colorama_init(autoreset=True)


def _severity_color(severity: Severity) -> str:
    return {
        Severity.HIGH: Fore.RED,
        Severity.MEDIUM: Fore.YELLOW,
        Severity.LOW: Fore.CYAN,
    }.get(severity, Fore.WHITE)


def _permission_color(perm: PermissionLevel) -> str:
    if perm in (PermissionLevel.OWNER, PermissionLevel.EDIT):
        return Fore.MAGENTA
    if perm == PermissionLevel.COMMENT:
        return Fore.CYAN
    return Fore.WHITE


def _member_type_color(mtype: MemberType) -> str:
    if mtype in (MemberType.ANYONE, MemberType.EXTERNAL):
        return Fore.RED
    if mtype == MemberType.DOMAIN:
        return Fore.YELLOW
    return Fore.GREEN


def _format_expiry(expiry: Optional[datetime]) -> str:
    if expiry is None:
        return f"{Fore.RED}未设置{Style.RESET_ALL}"
    return expiry.strftime("%Y-%m-%d")


def _format_reshare(can_reshare: bool) -> str:
    if can_reshare:
        return f"{Fore.RED}是{Style.RESET_ALL}"
    return f"{Fore.GREEN}否{Style.RESET_ALL}"


def _has_violation_for_member(violations: List[RuleViolation], member: Member, item: SharedItem) -> List[RuleViolation]:
    return [
        v for v in violations
        if v.member is not None
        and v.member.email == member.email
        and v.item_path == item.path
    ]


def _format_member_name(member: Member, item: SharedItem, violations: List[RuleViolation]) -> str:
    related = _has_violation_for_member(violations, member, item)
    color = _member_type_color(member.member_type)
    if related:
        severity = max(v.severity for v in related)
        color = _severity_color(severity)
        return f"{color}{member.name} <{member.email}>{Style.RESET_ALL}"
    return f"{color}{member.name} <{member.email}>{Style.RESET_ALL}"


def _print_item_table(item: SharedItem, violations: List[RuleViolation]):
    print()
    print(f"  {Fore.BLUE}{Style.BRIGHT}{item.name}{Style.RESET_ALL}")
    print(f"  {Fore.BLUE}{item.path}{Style.RESET_ALL}")
    if item.link:
        print(f"  {Fore.BLUE}链接: {item.link}{Style.RESET_ALL}")

    rows = []
    for member in item.members:
        related = _has_violation_for_member(violations, member, item)
        tags = ""
        if related:
            tag_list = [f"{_severity_color(v.severity)}{v.rule_id}{Style.RESET_ALL}" for v in related]
            tags = " ".join(tag_list)

        rows.append([
            _format_member_name(member, item, violations),
            f"{member.member_type.value}",
            f"{_permission_color(member.permission)}{member.permission.value}{Style.RESET_ALL}",
            _format_expiry(member.expiry),
            _format_reshare(member.can_reshare),
            tags,
        ])

    headers = [
        "成员",
        "类型",
        "权限",
        "到期时间",
        "转分享",
        "违规标记",
    ]
    print(tabulate(rows, headers=headers, tablefmt="simple"))


def _print_violation_summary(violations: List[RuleViolation]):
    if not violations:
        print()
        print(f"  {Fore.GREEN}[✓] 未发现违规权限配置{Style.RESET_ALL}")
        return

    high = [v for v in violations if v.severity == Severity.HIGH]
    medium = [v for v in violations if v.severity == Severity.MEDIUM]
    low = [v for v in violations if v.severity == Severity.LOW]

    print()
    print(f"  违规统计: {Fore.RED}HIGH={len(high)}{Style.RESET_ALL}  {Fore.YELLOW}MEDIUM={len(medium)}{Style.RESET_ALL}  {Fore.CYAN}LOW={len(low)}{Style.RESET_ALL}")

    if high:
        print()
        print(f"  {Fore.RED}{Style.BRIGHT}高危问题:{Style.RESET_ALL}")
        for v in high:
            member_info = f" ({v.member.email})" if v.member else ""
            print(f"    • {v.item_path}{member_info} — {v.rule_name}: {v.description}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="share-audit",
        description="极简共享文件夹权限审计工具",
        epilog="示例: share-audit scan /teams/engineering https://drive.example.com/s/xxx",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="扫描共享对象权限")
    scan_parser.add_argument(
        "targets",
        nargs="*",
        help="扫描目标: 文件夹路径、共享链接，或 @清单文件路径",
    )
    scan_parser.add_argument(
        "-f", "--file",
        action="append",
        default=[],
        help="从指定文件读取扫描目标列表（每行一个，可多次指定）",
    )
    scan_parser.add_argument(
        "-d", "--data",
        help="数据源文件路径（.json 或 .csv），从管理员导出的真实清单读取共享对象数据",
    )
    scan_parser.add_argument(
        "--domain",
        action="append",
        default=[],
        help="公司内网域名，用于自动识别外部邮箱，可多次指定，例如 --domain company.com",
    )
    scan_parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="递归扫描子目录",
    )
    scan_parser.add_argument(
        "-s", "--severity",
        action="append",
        default=None,
        help="按严重级别筛选，可多次指定，例如 -s HIGH -s MEDIUM",
    )
    scan_parser.add_argument(
        "-i", "--ignore",
        help="基线忽略白名单文件路径，每行一个匹配规则",
    )
    scan_parser.add_argument(
        "-o", "--report",
        help="输出文本报告到指定文件",
    )
    scan_parser.add_argument(
        "--json-out",
        help="导出机器可读结果到 JSON 文件",
    )
    scan_parser.add_argument(
        "--csv-out",
        help="导出机器可读结果到 CSV 文件",
    )
    scan_parser.add_argument(
        "-g", "--group",
        help="分组配置文件路径，每行格式：路径前缀 = 团队名称",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用彩色输出",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    list_parser = subparsers.add_parser("list-rules", help="列出所有审计规则")
    list_parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用彩色输出",
    )

    demo_parser = subparsers.add_parser("demo", help="运行演示扫描")
    demo_parser.add_argument(
        "-d", "--data",
        help="数据源文件路径（.json 或 .csv），覆盖默认演示数据",
    )
    demo_parser.add_argument(
        "--domain",
        action="append",
        default=[],
        help="公司内网域名，用于自动识别外部邮箱，可多次指定",
    )
    demo_parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        default=True,
        help=argparse.SUPPRESS,
    )
    demo_parser.add_argument(
        "-s", "--severity",
        action="append",
        default=None,
        help="按严重级别筛选，可多次指定",
    )
    demo_parser.add_argument(
        "-i", "--ignore",
        help="基线忽略白名单文件路径",
    )
    demo_parser.add_argument(
        "-o", "--report",
        help="输出文本报告到指定文件",
    )
    demo_parser.add_argument(
        "--json-out",
        help="导出机器可读结果到 JSON 文件",
    )
    demo_parser.add_argument(
        "--csv-out",
        help="导出机器可读结果到 CSV 文件",
    )
    demo_parser.add_argument(
        "-g", "--group",
        help="分组配置文件路径，每行格式：路径前缀 = 团队名称",
    )

    diff_parser = subparsers.add_parser("diff", help="对比两次扫描结果的趋势变化")
    diff_parser.add_argument(
        "old_json",
        help="旧扫描结果 JSON 文件路径",
    )
    diff_parser.add_argument(
        "new_json",
        help="新扫描结果 JSON 文件路径",
    )
    diff_parser.add_argument(
        "-s", "--severity",
        action="append",
        default=None,
        help="按严重级别筛选，可多次指定，例如 -s HIGH -s MEDIUM",
    )
    diff_parser.add_argument(
        "-o", "--report",
        help="输出对比报告到指定文件",
    )
    diff_parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用彩色输出",
    )

    return parser


def _parse_group_config(group_file: Optional[str]) -> Dict[str, str]:
    if not group_file:
        return {}
    groups = {}
    with open(group_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            prefix, name = line.split("=", 1)
            groups[prefix.strip()] = name.strip()
    return groups


def _get_group(path: str, groups: Dict[str, str]) -> str:
    if not groups:
        return "其他"
    for prefix, name in groups.items():
        if path.startswith(prefix):
            return name
    return "其他"


def _group_violations(
    violations: List[RuleViolation], groups: Dict[str, str]
) -> Dict[str, List[RuleViolation]]:
    result: Dict[str, List[RuleViolation]] = {}
    for v in violations:
        group = _get_group(v.item_path, groups)
        if group not in result:
            result[group] = []
        result[group].append(v)
    return result


def _cmd_list_rules(args: argparse.Namespace):
    if args.no_color:
        sys.stdout = open(sys.stdout.fileno(), mode="w", encoding="utf-8", buffering=1)
    _init_colorama()

    from .rules import DEFAULT_RULES

    print()
    print(f"  {Fore.BLUE}{Style.BRIGHT}内置审计规则列表{Style.RESET_ALL}")
    print()

    rules_meta = [
        ("R001", "任何人可访问", Severity.HIGH, "检测 member_type=anyone 的查看/评论/编辑权限"),
        ("R002", "外部用户可编辑", Severity.HIGH, "检测外部邮箱/外域用户拥有编辑或所有者权限"),
        ("R003", "权限未设到期时间", Severity.MEDIUM, "检测用户权限缺少到期日（永不过期）"),
        ("R004", "允许转分享", Severity.MEDIUM, "检测外部用户或公开链接拥有转分享权限"),
    ]
    rows = [
        [
            f"{_severity_color(s)}{rid}{Style.RESET_ALL}",
            name,
            f"{_severity_color(s)}{s.value}{Style.RESET_ALL}",
            desc,
        ]
        for rid, name, s, desc in rules_meta
    ]
    print(tabulate(rows, headers=["规则ID", "名称", "严重级别", "说明"], tablefmt="simple"))
    print()


def _build_provider(data_file: Optional[str], domains: Optional[List[str]]) -> DataProvider:
    if data_file:
        return FileDataProvider(data_file, company_domains=domains or None)
    return MockDataProvider()


def _build_recheck_cmd(
    target: str,
    data_file: Optional[str],
    domains: Optional[List[str]],
    recursive: bool,
    severity_filter: Optional[List[str]],
    ignore_file: Optional[str],
) -> str:
    parts = ["python", "share_audit.py", "scan"]
    if data_file:
        parts.extend(["-d", _shell_quote(data_file)])
    if domains:
        for d in domains:
            parts.extend(["--domain", d])
    if recursive:
        parts.append("-r")
    if severity_filter:
        for s in severity_filter:
            parts.extend(["-s", s])
    if ignore_file:
        parts.extend(["-i", _shell_quote(ignore_file)])
    parts.append(_shell_quote(target))
    return " ".join(parts)


def _shell_quote(s: str) -> str:
    if " " in s or '"' in s or "'" in s:
        return '"' + s.replace('"', '\\"') + '"'
    return s


def _member_to_dict(member: Member) -> dict:
    return {
        "name": member.name,
        "email": member.email,
        "member_type": member.member_type.value,
        "permission": member.permission.value,
        "can_reshare": member.can_reshare,
        "expiry": member.expiry.strftime("%Y-%m-%d %H:%M:%S") if member.expiry else None,
    }


def _item_to_dict(item: SharedItem, violations: List[RuleViolation], ignored: List[RuleViolation]) -> dict:
    item_violations = [v for v in violations if v.item_path == item.path]
    item_ignored = [v for v in ignored if v.item_path == item.path]
    member_dicts = []
    for m in item.members:
        mv = [v for v in item_violations if v.member and v.member.email == m.email]
        mi = [v for v in item_ignored if v.member and v.member.email == m.email]
        md = _member_to_dict(m)
        md["violations"] = [
            {"rule_id": v.rule_id, "rule_name": v.rule_name, "severity": v.severity.value, "ignored": False}
            for v in mv
        ]
        md["violations"].extend([
            {"rule_id": v.rule_id, "rule_name": v.rule_name, "severity": v.severity.value, "ignored": True}
            for v in mi
        ])
        member_dicts.append(md)
    return {
        "id": item.id,
        "name": item.name,
        "path": item.path,
        "item_type": item.item_type,
        "link": item.link,
        "members": member_dicts,
        "violation_count": len(item_violations),
        "ignored_count": len(item_ignored),
    }


def _violation_to_dict(v: RuleViolation, ignored: bool = False) -> dict:
    return {
        "rule_id": v.rule_id,
        "rule_name": v.rule_name,
        "severity": v.severity.value,
        "item_name": v.item_name,
        "item_path": v.item_path,
        "member_email": v.member.email if v.member else None,
        "member_permission": v.member.permission.value if v.member else None,
        "description": v.description,
        "suggestion": v.suggestion,
        "recheck_cmd": v.recheck_cmd,
        "ignored": ignored,
    }


def _write_json_output(
    path: str,
    items: List[SharedItem],
    violations: List[RuleViolation],
    ignored_violations: List[RuleViolation],
    not_found: List[str],
    errors: List[str],
    data_file: Optional[str],
    domains: Optional[List[str]],
    severity_filter: Optional[List[str]],
) -> None:
    data = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "data_source": data_file,
        "company_domains": domains or [],
        "severity_filter": severity_filter or [],
        "summary": {
            "total_items": len(items),
            "active_violations": len(violations),
            "ignored_violations": len(ignored_violations),
            "high": sum(1 for v in violations if v.severity == Severity.HIGH),
            "medium": sum(1 for v in violations if v.severity == Severity.MEDIUM),
            "low": sum(1 for v in violations if v.severity == Severity.LOW),
            "not_found_targets": len(not_found),
            "errors": len(errors),
        },
        "items": [_item_to_dict(item, violations, ignored_violations) for item in items],
        "violations": [_violation_to_dict(v, False) for v in violations],
        "ignored_violations": [_violation_to_dict(v, True) for v in ignored_violations],
        "not_found_targets": not_found,
        "errors": errors,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _write_csv_output(
    path: str,
    items: List[SharedItem],
    violations: List[RuleViolation],
    ignored_violations: List[RuleViolation],
    not_found: List[str],
    errors: List[str],
) -> None:
    rows = []
    all_violations = violations + ignored_violations

    for item in items:
        for member in item.members:
            member_violations = [
                v for v in all_violations
                if v.member and v.member.email == member.email and v.item_path == item.path
            ]
            is_ignored_list = [v in ignored_violations for v in member_violations]

            base_row = {
                "type": "member",
                "item_id": item.id,
                "item_name": item.name,
                "item_path": item.path,
                "item_type": item.item_type,
                "item_link": item.link or "",
                "member_name": member.name,
                "member_email": member.email,
                "member_type": member.member_type.value,
                "permission": member.permission.value,
                "can_reshare": "true" if member.can_reshare else "false",
                "expiry": member.expiry.strftime("%Y-%m-%d") if member.expiry else "",
                "has_violation": "true" if member_violations else "false",
                "violation_count": len([v for v in member_violations if v not in ignored_violations]),
                "ignored_count": len([v for v in member_violations if v in ignored_violations]),
            }

            if not member_violations:
                base_row.update({
                    "rule_id": "",
                    "rule_name": "",
                    "severity": "",
                    "description": "",
                    "suggestion": "",
                    "recheck_cmd": "",
                    "ignored": "",
                })
                rows.append(base_row)
            else:
                for v, ignored in zip(member_violations, is_ignored_list):
                    row = base_row.copy()
                    row.update({
                        "type": "violation",
                        "rule_id": v.rule_id,
                        "rule_name": v.rule_name,
                        "severity": v.severity.value,
                        "description": v.description,
                        "suggestion": v.suggestion,
                        "recheck_cmd": v.recheck_cmd,
                        "ignored": "true" if ignored else "false",
                    })
                    rows.append(row)

    for nf in not_found:
        rows.append({
            "type": "not_found",
            "item_id": "",
            "item_name": "",
            "item_path": nf,
            "item_type": "",
            "item_link": "",
            "member_name": "",
            "member_email": "",
            "member_type": "",
            "permission": "",
            "can_reshare": "",
            "expiry": "",
            "has_violation": "",
            "violation_count": "",
            "ignored_count": "",
            "rule_id": "",
            "rule_name": "",
            "severity": "",
            "description": "未在数据源中找到该目标",
            "suggestion": "核对路径/链接拼写或重新导出数据源",
            "recheck_cmd": "",
            "ignored": "",
        })

    for e in errors:
        rows.append({
            "type": "error",
            "item_id": "",
            "item_name": "",
            "item_path": "",
            "item_type": "",
            "item_link": "",
            "member_name": "",
            "member_email": "",
            "member_type": "",
            "permission": "",
            "can_reshare": "",
            "expiry": "",
            "has_violation": "",
            "violation_count": "",
            "ignored_count": "",
            "rule_id": "",
            "rule_name": "",
            "severity": "",
            "description": e,
            "suggestion": "",
            "recheck_cmd": "",
            "ignored": "",
        })

    fieldnames = [
        "type", "item_id", "item_name", "item_path", "item_type", "item_link",
        "member_name", "member_email", "member_type", "permission", "can_reshare", "expiry",
        "has_violation", "violation_count", "ignored_count",
        "rule_id", "rule_name", "severity", "description", "suggestion", "recheck_cmd", "ignored",
    ]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _parse_ignore_file(ignore_file: Optional[str]) -> List[str]:
    if not ignore_file:
        return []
    if not os.path.exists(ignore_file):
        return []
    patterns: List[str] = []
    with open(ignore_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line.lower())
    return patterns


def _is_ignored(violation: RuleViolation, ignore_patterns: List[str]) -> bool:
    if not ignore_patterns:
        return False
    key_items = [
        violation.item_path.lower(),
        violation.rule_id.lower(),
        violation.member.email.lower() if violation.member else "",
        f"{violation.rule_id}:{violation.item_path}".lower(),
        f"{violation.rule_id}:{violation.member.email}".lower() if violation.member else "",
    ]
    if violation.member:
        key_items.append(f"{violation.item_path}:{violation.member.email}".lower())
        key_items.append(f"{violation.rule_id}:{violation.item_path}:{violation.member.email}".lower())
    for pattern in ignore_patterns:
        for key in key_items:
            if pattern in key:
                return True
    return False


def _filter_by_severity(
    violations: List[RuleViolation],
    severity_filter: Optional[List[str]],
) -> List[RuleViolation]:
    if not severity_filter:
        return violations
    allowed = {s.upper() for s in severity_filter}
    return [v for v in violations if v.severity.value.upper() in allowed]


def _finalize_violations(
    violations: List[RuleViolation],
    data_file: Optional[str],
    domains: Optional[List[str]],
    recursive: bool,
    severity_filter: Optional[List[str]],
    ignore_file: Optional[str],
) -> None:
    for v in violations:
        v.recheck_cmd = _build_recheck_cmd(
            v.recheck_cmd, data_file, domains, recursive, severity_filter, ignore_file
        )


def _run_audit(
    targets: List[ScanTarget],
    provider: DataProvider,
    recursive: bool,
    report_path: Optional[str],
    company_domains: Optional[List[str]] = None,
    data_file: Optional[str] = None,
    severity_filter: Optional[List[str]] = None,
    ignore_file: Optional[str] = None,
    json_out: Optional[str] = None,
    csv_out: Optional[str] = None,
    group_config: Optional[Dict[str, str]] = None,
) -> int:
    scanner = Scanner(provider, recursive=recursive)
    scan_results = scanner.scan(targets)

    if company_domains is None:
        company_domains = getattr(provider, "company_domains", None) or []
    rule_engine = RuleEngine(company_domains=company_domains)

    all_items: List[SharedItem] = []
    seen_ids = set()
    all_errors: List[str] = []
    all_not_found: List[str] = []

    for sr in scan_results:
        for item in sr.items:
            if item.id not in seen_ids:
                all_items.append(item)
                seen_ids.add(item.id)
        all_errors.extend(sr.errors)
        all_not_found.extend(sr.not_found)

    ignore_patterns = _parse_ignore_file(ignore_file)

    total_targets = len(targets)
    matched_targets = total_targets - len(all_errors) - len(all_not_found)
    provider_name = getattr(provider, "file_path", "(内置演示数据)")
    item_count = getattr(provider, "item_count", "?")
    print()
    print(f"  {Fore.BLUE}数据源:{Style.RESET_ALL} {provider_name}  共 {item_count} 个共享对象")
    print(f"  {Fore.BLUE}扫描目标:{Style.RESET_ALL} {total_targets} 个  命中 {matched_targets}  未找到 {len(all_not_found)}  错误 {len(all_errors)}")
    if severity_filter:
        print(f"  {Fore.BLUE}级别筛选:{Style.RESET_ALL} {', '.join(severity_filter)}")
    if ignore_patterns:
        print(f"  {Fore.BLUE}忽略白名单:{Style.RESET_ALL} {len(ignore_patterns)} 条规则")

    if all_errors:
        print()
        for e in all_errors:
            print(f"  {Fore.RED}[错误] {e}{Style.RESET_ALL}")

    if all_not_found:
        print()
        print(f"  {Fore.YELLOW}[未找到目标]{Style.RESET_ALL} 以下目标在数据源中不存在，请核对路径/链接拼写或重新导出：")
        for nf in all_not_found:
            print(f"    • {nf}")

    if not all_items:
        print()
        print(f"  {Fore.RED}未扫描到任何共享对象{Style.RESET_ALL}")
        return 1

    all_violations = rule_engine.check(all_items)

    ignored_violations: List[RuleViolation] = []
    active_violations: List[RuleViolation] = []
    for v in all_violations:
        if _is_ignored(v, ignore_patterns):
            ignored_violations.append(v)
        else:
            active_violations.append(v)

    filtered_violations = _filter_by_severity(active_violations, severity_filter)

    _finalize_violations(filtered_violations, data_file, company_domains, recursive, severity_filter, ignore_file)
    _finalize_violations(ignored_violations, data_file, company_domains, recursive, severity_filter, ignore_file)

    seen_paths = set()
    for item in all_items:
        if item.path in seen_paths:
            continue
        item_filtered = [v for v in filtered_violations if v.item_path == item.path]
        if severity_filter and not item_filtered:
            continue
        _print_item_table(item, filtered_violations)
        seen_paths.add(item.path)

    if ignored_violations:
        print()
        print(f"  {Fore.CYAN}[已忽略]{Style.RESET_ALL} 基线白名单命中 {len(ignored_violations)} 条：")
        seen_ignored = set()
        for v in ignored_violations:
            key = f"{v.item_path}:{v.rule_id}:{v.member.email if v.member else ''}"
            if key not in seen_ignored:
                seen_ignored.add(key)
                print(f"    • {v.item_path} | {v.rule_name} | {v.member.email if v.member else ''}")
                seen_ignored.add(key)

    _print_violation_summary(filtered_violations)

    if group_config:
        grouped = _group_violations(filtered_violations, group_config)
        ignored_grouped = _group_violations(ignored_violations, group_config)
        print()
        print(f"  {Fore.BLUE}{Style.BRIGHT}按团队分组统计:{Style.RESET_ALL}")
        for group_name in sorted(grouped.keys()):
            g_violations = grouped[group_name]
            g_high = sum(1 for v in g_violations if v.severity == Severity.HIGH)
            g_med = sum(1 for v in g_violations if v.severity == Severity.MEDIUM)
            g_low = sum(1 for v in g_violations if v.severity == Severity.LOW)
            g_ignored = len(ignored_grouped.get(group_name, []))
            print(f"    {Fore.BLUE}• {group_name}:{Style.RESET_ALL} HIGH={g_high} MEDIUM={g_med} LOW={g_low}  已忽略={g_ignored}")

    if report_path:
        rep = ReportGenerator()
        rep.generate(
            filtered_violations,
            output_path=report_path,
            ignored_violations=ignored_violations,
            not_found_targets=all_not_found,
            group_config=group_config,
        )
        print()
        print(f"  {Fore.GREEN}文本报告已生成: {report_path}{Style.RESET_ALL}")

    if json_out:
        _write_json_output(
            json_out, all_items, filtered_violations, ignored_violations, all_not_found, all_errors,
            data_file, company_domains, severity_filter
        )
        print(f"  {Fore.GREEN}JSON 结果已导出: {json_out}{Style.RESET_ALL}")

    if csv_out:
        _write_csv_output(
            csv_out, all_items, filtered_violations, ignored_violations, all_not_found, all_errors
        )
        print(f"  {Fore.GREEN}CSV 结果已导出: {csv_out}{Style.RESET_ALL}")

    high_count = sum(1 for v in filtered_violations if v.severity == Severity.HIGH)
    return 1 if high_count > 0 else 0


def _cmd_scan(args: argparse.Namespace):
    if not args.no_color:
        _init_colorama()

    all_raw_targets = list(args.targets) if args.targets else []
    for list_file in args.file:
        all_raw_targets.append("@" + list_file)

    targets = parse_targets_from_args(all_raw_targets)
    if not targets:
        print(f"{Fore.RED}未提供有效的扫描目标。使用 -f 指定目标清单或直接传入路径/共享链接{Style.RESET_ALL}")
        return 1

    try:
        provider = _build_provider(args.data, args.domain)
    except (FileNotFoundError, ValueError) as exc:
        print(f"{Fore.RED}数据源加载失败: {exc}{Style.RESET_ALL}")
        return 2

    group_config = _parse_group_config(args.group)

    return _run_audit(
        targets,
        provider,
        args.recursive,
        args.report,
        company_domains=args.domain,
        data_file=args.data,
        severity_filter=args.severity,
        ignore_file=args.ignore,
        json_out=args.json_out,
        csv_out=args.csv_out,
        group_config=group_config if group_config else None,
    )


def _cmd_demo(args: argparse.Namespace):
    _init_colorama()

    print()
    print(f"  {Fore.BLUE}{Style.BRIGHT}=== 共享文件夹权限审计演示 ==={Style.RESET_ALL}")
    print()

    demo_targets = [
        "/teams/engineering",
        "/teams/legal/contracts",
        "https://drive.example.com/s/fin-q2-draft",
    ]

    targets = [ScanTarget(raw=t, target_type="path" if t.startswith("/") else "link", value=t) for t in demo_targets]

    try:
        provider = _build_provider(args.data, args.domain)
    except (FileNotFoundError, ValueError) as exc:
        print(f"{Fore.RED}数据源加载失败: {exc}{Style.RESET_ALL}")
        return 2

    group_config = _parse_group_config(args.group)

    return _run_audit(
        targets,
        provider,
        recursive=True,
        report_path=args.report,
        company_domains=args.domain,
        data_file=args.data,
        severity_filter=args.severity,
        ignore_file=args.ignore,
        json_out=args.json_out,
        csv_out=args.csv_out,
        group_config=group_config if group_config else None,
    )


def _cmd_diff(args: argparse.Namespace):
    if not args.no_color:
        _init_colorama()

    from .diff import compare_json_files, ChangeType

    print()
    print(f"  {Fore.BLUE}{Style.BRIGHT}=== 共享权限巡检趋势对比 ==={Style.RESET_ALL}")
    print()

    try:
        diff_result = compare_json_files(args.old_json, args.new_json, args.severity)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"  {Fore.RED}读取扫描结果失败: {exc}{Style.RESET_ALL}")
        return 2

    s = diff_result.summary
    print(f"  {Fore.BLUE}旧扫描:{Style.RESET_ALL} {diff_result.old_file}  ({diff_result.old_generated_at})")
    print(f"  {Fore.BLUE}新扫描:{Style.RESET_ALL} {diff_result.new_file}  ({diff_result.new_generated_at})")
    print()
    print(f"  {Fore.BLUE}变化汇总:{Style.RESET_ALL}")
    print(f"    {Fore.GREEN}+ 新增:{Style.RESET_ALL} HIGH={s['new']['HIGH']} MEDIUM={s['new']['MEDIUM']} LOW={s['new']['LOW']} TOTAL={s['new']['TOTAL']}")
    print(f"    {Fore.CYAN}- 已修复:{Style.RESET_ALL} HIGH={s['fixed']['HIGH']} MEDIUM={s['fixed']['MEDIUM']} LOW={s['fixed']['LOW']} TOTAL={s['fixed']['TOTAL']}")
    print(f"    {Fore.YELLOW}• 仍存在:{Style.RESET_ALL} HIGH={s['existing']['HIGH']} MEDIUM={s['existing']['MEDIUM']} LOW={s['existing']['LOW']} TOTAL={s['existing']['TOTAL']}")

    sections = [
        (diff_result.new_violations, ChangeType.NEW, Fore.GREEN, "+ 新增风险"),
        (diff_result.fixed_violations, ChangeType.FIXED, Fore.CYAN, "- 已修复"),
        (diff_result.existing_violations, ChangeType.EXISTING, Fore.YELLOW, "• 仍存在"),
    ]

    for violations, change_type, color, title in sections:
        if not violations:
            continue
        print()
        print(f"  {color}{Style.BRIGHT}{title}（{len(violations)} 条）{Style.RESET_ALL}")
        for idx, v in enumerate(violations, 1):
            member_info = f" ({v.member_email})" if v.member_email else ""
            print(f"    {color}{idx:>3}.{Style.RESET_ALL} [{v.severity.value}] {v.rule_name}  {v.item_path}{member_info}")

    if args.report:
        from .report import ReportGenerator
        generator = ReportGenerator()
        report = generator.generate_diff_report(diff_result, output_path=args.report)
        print()
        print(f"  {Fore.GREEN}对比报告已导出: {args.report}{Style.RESET_ALL}")

    return 1 if s["new"]["TOTAL"] > 0 else 0


def audit_main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "list-rules":
        return _cmd_list_rules(args)
    elif args.command == "demo":
        return _cmd_demo(args)
    elif args.command == "diff":
        return _cmd_diff(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(audit_main())
