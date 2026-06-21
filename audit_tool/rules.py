from typing import Callable, List, Optional

from .models import (
    Member,
    MemberType,
    PermissionLevel,
    RuleViolation,
    SharedItem,
    Severity,
)


RuleFn = Callable[[SharedItem, Member], List[RuleViolation]]


def _is_external_email(email: str, company_domains: Optional[List[str]] = None) -> bool:
    if not company_domains:
        return False
    if "@" not in email:
        return False
    domain = email.split("@")[-1].lower()
    return domain not in [d.lower() for d in company_domains]


def _base_violation(
    rule_id: str,
    rule_name: str,
    severity: Severity,
    item: SharedItem,
    member: Member,
    description: str,
    suggestion: str,
) -> RuleViolation:
    if item.path.endswith("/"):
        recheck_target = item.path
    else:
        recheck_target = item.link if item.link else item.path

    recheck_cmd = f"share-audit scan \"{recheck_target}\""

    return RuleViolation(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        item_name=item.name,
        item_path=item.path,
        description=description,
        suggestion=suggestion,
        recheck_cmd=recheck_cmd,
        member=member,
    )


def rule_anyone_view(item: SharedItem, member: Member) -> List[RuleViolation]:
    if member.member_type == MemberType.ANYONE and member.permission in (
        PermissionLevel.VIEW,
        PermissionLevel.COMMENT,
        PermissionLevel.EDIT,
    ):
        return [_base_violation(
            rule_id="R001",
            rule_name="任何人可访问",
            severity=Severity.HIGH,
            item=item,
            member=member,
            description=f"对象对任何人开放【{member.permission.value}】权限",
            suggestion="立即关闭公开访问，改为指定内部用户或设置访问白名单",
        )]
    return []


def make_rule_external_edit(company_domains: Optional[List[str]] = None) -> RuleFn:
    def rule_external_edit(item: SharedItem, member: Member) -> List[RuleViolation]:
        if member.member_type == MemberType.EXTERNAL and member.permission in (
            PermissionLevel.EDIT,
            PermissionLevel.OWNER,
        ):
            return [_base_violation(
                rule_id="R002",
                rule_name="外部用户可编辑",
                severity=Severity.HIGH,
                item=item,
                member=member,
                description=f"外部用户 {member.email} 拥有【{member.permission.value}】权限",
                suggestion="降为查看权限或移除用户，必要时设定期限并开启二次验证",
            )]
        if company_domains and _is_external_email(member.email, company_domains) and member.permission in (
            PermissionLevel.EDIT,
            PermissionLevel.OWNER,
        ):
            return [_base_violation(
                rule_id="R002",
                rule_name="外部邮箱可编辑",
                severity=Severity.HIGH,
                item=item,
                member=member,
                description=f"外部邮箱 {member.email} 拥有【{member.permission.value}】权限",
                suggestion="核查是否为外包/外包账号，降权或添加有效期限制",
            )]
        return []
    return rule_external_edit


def rule_no_expiry(item: SharedItem, member: Member) -> List[RuleViolation]:
    if member.expiry is None and member.member_type not in (MemberType.ANYONE,):
        if member.permission in (
            PermissionLevel.EDIT,
            PermissionLevel.OWNER,
            PermissionLevel.COMMENT,
            PermissionLevel.VIEW,
        ):
            return [_base_violation(
                rule_id="R003",
                rule_name="权限未设到期时间",
                severity=Severity.MEDIUM,
                item=item,
                member=member,
                description=f"用户 {member.email} 的【{member.permission.value}】权限无到期时间",
                suggestion="根据项目周期设置合理的到期时间，例如 90 天内",
            )]
    return []


def rule_reshare_enabled(item: SharedItem, member: Member) -> List[RuleViolation]:
    if member.can_reshare and member.member_type in (
        MemberType.EXTERNAL,
        MemberType.ANYONE,
    ):
        return [_base_violation(
            rule_id="R004",
            rule_name="允许转分享",
            severity=Severity.MEDIUM,
            item=item,
            member=member,
            description=f"{member.email} 拥有【{member.permission.value}】且允许转分享",
            suggestion="关闭转分享权限，防止权限扩散",
        )]
    return []


def _build_default_rules(company_domains: Optional[List[str]] = None) -> List[RuleFn]:
    return [
        rule_anyone_view,
        make_rule_external_edit(company_domains),
        rule_no_expiry,
        rule_reshare_enabled,
    ]


DEFAULT_RULES: List[RuleFn] = _build_default_rules()


class RuleEngine:
    def __init__(self, rules: List[RuleFn] = None, company_domains: Optional[List[str]] = None):
        self.company_domains = company_domains or []
        if rules is not None:
            self.rules = rules
        else:
            self.rules = _build_default_rules(company_domains)

    def check(self, items: List[SharedItem]) -> List[RuleViolation]:
        violations: List[RuleViolation] = []
        for item in items:
            for member in item.members:
                for rule in self.rules:
                    violations.extend(rule(item, member))
        return violations

    def check_item(self, item: SharedItem) -> List[RuleViolation]:
        return self.check([item])
