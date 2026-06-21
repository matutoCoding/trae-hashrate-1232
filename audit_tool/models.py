from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class PermissionLevel(str, Enum):
    OWNER = "owner"
    EDIT = "edit"
    COMMENT = "comment"
    VIEW = "view"
    NONE = "none"


class MemberType(str, Enum):
    USER = "user"
    GROUP = "group"
    ANYONE = "anyone"
    DOMAIN = "domain"
    EXTERNAL = "external"


@dataclass
class Member:
    name: str
    email: str
    member_type: MemberType
    permission: PermissionLevel
    can_reshare: bool = False
    expiry: Optional[datetime] = None


@dataclass
class SharedItem:
    id: str
    name: str
    path: str
    item_type: str
    link: Optional[str] = None
    members: List[Member] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class ScanTarget:
    raw: str
    target_type: str
    value: str


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class RuleViolation:
    rule_id: str
    rule_name: str
    severity: Severity
    item_name: str
    item_path: str
    description: str
    suggestion: str
    recheck_cmd: str
    member: Optional[Member] = None
