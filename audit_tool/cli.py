import argparse
import sys
from datetime import datetime
from typing import List, Optional

from colorama import Fore, Style, init as colorama_init
from tabulate import tabulate

from .data_provider import DataProvider, MockDataProvider
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
        "-r", "--recursive",
        action="store_true",
        help="递归扫描子目录",
    )
    scan_parser.add_argument(
        "-o", "--report",
        help="输出文本报告到指定文件",
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
        "-o", "--report",
        help="输出文本报告到指定文件",
    )

    return parser


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


def _run_audit(
    targets: List[ScanTarget],
    provider: DataProvider,
    recursive: bool,
    report_path: Optional[str],
) -> int:
    scanner = Scanner(provider, recursive=recursive)
    scan_results = scanner.scan(targets)
    rule_engine = RuleEngine()

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

    all_violations = rule_engine.check(all_items)

    if all_errors:
        print()
        for e in all_errors:
            print(f"  {Fore.RED}[错误] {e}{Style.RESET_ALL}")

    if all_not_found:
        print()
        for nf in all_not_found:
            print(f"  {Fore.YELLOW}[警告] 未找到: {nf}{Style.RESET_ALL}")

    if not all_items:
        print()
        print(f"  {Fore.RED}未扫描到任何共享对象{Style.RESET_ALL}")
        return 1

    seen_paths = set()
    for item in all_items:
        if item.path not in seen_paths:
            _print_item_table(item, all_violations)
            seen_paths.add(item.path)

    _print_violation_summary(all_violations)

    if report_path:
        rep = ReportGenerator()
        rep.generate(all_violations, output_path=report_path)
        print()
        print(f"  {Fore.GREEN}文本报告已生成: {report_path}{Style.RESET_ALL}")

    high_count = sum(1 for v in all_violations if v.severity == Severity.HIGH)
    return 1 if high_count > 0 else 0


def _cmd_scan(args: argparse.Namespace):
    if not args.no_color:
        _init_colorama()

    all_raw_targets = list(args.targets) if args.targets else []
    for list_file in args.file:
        all_raw_targets.append("@" + list_file)

    targets = parse_targets_from_args(all_raw_targets)
    if not targets:
        print(f"{Fore.RED}未提供有效的扫描目标{Style.RESET_ALL}")
        return 1

    provider = MockDataProvider()
    return _run_audit(targets, provider, args.recursive, args.report)


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

    provider = MockDataProvider()
    return _run_audit(targets, provider, recursive=True, report_path=args.report)


def audit_main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "list-rules":
        return _cmd_list_rules(args)
    elif args.command == "demo":
        return _cmd_demo(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(audit_main())
