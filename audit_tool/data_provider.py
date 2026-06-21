from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import csv
import json
import os

from .models import (
    Member,
    MemberType,
    PermissionLevel,
    SharedItem,
    ScanTarget,
)


class DataProvider(ABC):
    @abstractmethod
    def fetch_by_path(self, path: str) -> Optional[SharedItem]:
        pass

    @abstractmethod
    def fetch_by_link(self, link: str) -> Optional[SharedItem]:
        pass

    @abstractmethod
    def fetch_children(self, path: str, recursive: bool = False) -> List[SharedItem]:
        pass


class MockDataProvider(DataProvider):
    def __init__(self):
        self._items: Dict[str, SharedItem] = {}
        self._link_index: Dict[str, str] = {}
        self._init_mock_data()

    def _init_mock_data(self):
        now = datetime.now()

        self._add_item(SharedItem(
            id="space-001",
            name="研发团队空间",
            path="/teams/engineering",
            item_type="space",
            link="https://drive.example.com/s/eng-public",
            created_at=now - timedelta(days=180),
            updated_at=now - timedelta(days=7),
            members=[
                Member("研发组", "eng@company.com", MemberType.GROUP, PermissionLevel.EDIT, True, None),
                Member("任何人", "anyone", MemberType.ANYONE, PermissionLevel.VIEW, True, None),
            ],
        ))

        self._add_item(SharedItem(
            id="proj-001",
            name="核心算法项目",
            path="/teams/engineering/algorithm-core",
            item_type="folder",
            link="https://drive.example.com/s/algo-core",
            created_at=now - timedelta(days=90),
            updated_at=now - timedelta(days=2),
            members=[
                Member("张工", "zhang.eng@company.com", MemberType.USER, PermissionLevel.OWNER, True, None),
                Member("李工", "li.eng@company.com", MemberType.USER, PermissionLevel.EDIT, True, now + timedelta(days=30)),
                Member("外包顾问", "consultant@external-vendor.com", MemberType.EXTERNAL, PermissionLevel.EDIT, False, None),
            ],
        ))

        self._add_item(SharedItem(
            id="proj-002",
            name="产品文档",
            path="/teams/engineering/product-docs",
            item_type="folder",
            link=None,
            created_at=now - timedelta(days=60),
            updated_at=now - timedelta(days=1),
            members=[
                Member("产品组", "pm@company.com", MemberType.GROUP, PermissionLevel.EDIT, True, now + timedelta(days=90)),
                Member("设计组", "design@company.com", MemberType.GROUP, PermissionLevel.COMMENT, False, now + timedelta(days=60)),
            ],
        ))

        self._add_item(SharedItem(
            id="proj-003",
            name="客户合同档案",
            path="/teams/legal/contracts",
            item_type="folder",
            link="https://drive.example.com/s/customer-contracts",
            created_at=now - timedelta(days=365),
            updated_at=now - timedelta(days=14),
            members=[
                Member("法务组", "legal@company.com", MemberType.GROUP, PermissionLevel.EDIT, True, None),
                Member("任何人", "anyone", MemberType.ANYONE, PermissionLevel.VIEW, False, None),
                Member("临时审计", "auditor@thirdparty.cn", MemberType.EXTERNAL, PermissionLevel.VIEW, False, None),
            ],
        ))

        self._add_item(SharedItem(
            id="share-001",
            name="季度财报草稿",
            path="/finance/quarterly-reports/Q2-draft",
            item_type="file",
            link="https://drive.example.com/s/fin-q2-draft",
            created_at=now - timedelta(days=10),
            updated_at=now - timedelta(hours=5),
            members=[
                Member("财务总监", "cfo@company.com", MemberType.USER, PermissionLevel.OWNER, True, None),
                Member("外部审计合伙人", "audit-partner@big4.com", MemberType.EXTERNAL, PermissionLevel.EDIT, True, None),
            ],
        ))

        self._add_item(SharedItem(
            id="proj-004",
            name="市场素材库",
            path="/teams/marketing/assets",
            item_type="folder",
            link="https://drive.example.com/s/marketing-assets",
            created_at=now - timedelta(days=120),
            updated_at=now - timedelta(days=3),
            members=[
                Member("市场组", "marketing@company.com", MemberType.GROUP, PermissionLevel.EDIT, True, now + timedelta(days=180)),
            ],
        ))

    def _add_item(self, item: SharedItem):
        self._items[item.path] = item
        if item.link:
            self._link_index[item.link] = item.path

    def fetch_by_path(self, path: str) -> Optional[SharedItem]:
        return self._items.get(path)

    def fetch_by_link(self, link: str) -> Optional[SharedItem]:
        path = self._link_index.get(link)
        return self._items.get(path) if path else None

    def fetch_children(self, path: str, recursive: bool = False) -> List[SharedItem]:
        prefix = path.rstrip("/") + "/"
        results = []
        for item_path, item in self._items.items():
            if item_path.startswith(prefix):
                depth = item_path[len(prefix):].count("/")
                if recursive or depth == 0:
                    results.append(item)
        return results


def _parse_expiry(value: Optional[str]) -> Optional[datetime]:
    if not value or not str(value).strip():
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _parse_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "y", "是")


def _parse_member_type(value: str) -> MemberType:
    mapping = {
        "user": MemberType.USER,
        "group": MemberType.GROUP,
        "anyone": MemberType.ANYONE,
        "domain": MemberType.DOMAIN,
        "external": MemberType.EXTERNAL,
    }
    return mapping.get(str(value).strip().lower(), MemberType.USER)


def _parse_permission(value: str) -> PermissionLevel:
    mapping = {
        "owner": PermissionLevel.OWNER,
        "edit": PermissionLevel.EDIT,
        "comment": PermissionLevel.COMMENT,
        "view": PermissionLevel.VIEW,
        "none": PermissionLevel.NONE,
        "readonly": PermissionLevel.VIEW,
        "read": PermissionLevel.VIEW,
        "write": PermissionLevel.EDIT,
    }
    return mapping.get(str(value).strip().lower(), PermissionLevel.VIEW)


class FileDataProvider(DataProvider):
    """从本地 JSON 或 CSV 文件读取共享对象数据。

    JSON 格式（推荐）：
    {
      "company_domains": ["company.com"],
      "items": [
        {
          "id": "item-001",
          "name": "项目目录名",
          "path": "/teams/engineering/xxx",
          "item_type": "folder",
          "link": "https://drive.example.com/s/xxx",
          "created_at": "2026-01-01",
          "updated_at": "2026-06-01",
          "members": [
            {
              "name": "张三",
              "email": "zhangsan@company.com",
              "member_type": "user",
              "permission": "edit",
              "can_reshare": true,
              "expiry": "2026-09-30"
            }
          ]
        }
      ]
    }

    CSV 格式（一行一个成员，共享对象字段重复）：
    id,name,path,item_type,link,member_name,member_email,member_type,permission,can_reshare,expiry
    """

    def __init__(self, file_path: str, company_domains: Optional[List[str]] = None):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"数据源文件不存在: {file_path}")
        self.file_path = file_path
        self.company_domains = [d.lower() for d in (company_domains or [])]
        self._items: Dict[str, SharedItem] = {}
        self._link_index: Dict[str, str] = {}
        self._load()

    def _load(self):
        ext = os.path.splitext(self.file_path)[1].lower()
        if ext == ".json":
            self._load_json()
        elif ext in (".csv", ".tsv"):
            self._load_csv()
        else:
            raise ValueError(f"不支持的数据源格式: {ext}（仅支持 .json / .csv）")

    def _load_json(self):
        with open(self.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            if "company_domains" in data and not self.company_domains:
                self.company_domains = [d.lower() for d in data["company_domains"]]
            items_raw = data.get("items", [])
        elif isinstance(data, list):
            items_raw = data
        else:
            raise ValueError("JSON 格式错误：顶层应为数组或包含 items 字段的对象")

        for raw in items_raw:
            item = self._build_item_from_json(raw)
            self._add_item(item)

    def _build_item_from_json(self, raw: dict) -> SharedItem:
        members = []
        for m in raw.get("members", []):
            members.append(self._build_member(m))

        item_id = raw.get("id") or raw.get("path") or raw.get("link")
        return SharedItem(
            id=str(item_id),
            name=str(raw.get("name", "")),
            path=str(raw.get("path", "")),
            item_type=str(raw.get("item_type", "folder")),
            link=raw.get("link") or None,
            created_at=_parse_expiry(raw.get("created_at")),
            updated_at=_parse_expiry(raw.get("updated_at")),
            members=members,
        )

    def _load_csv(self):
        item_groups: Dict[str, dict] = {}
        member_rows_by_item: Dict[str, List[dict]] = {}

        delimiter = "\t" if self.file_path.lower().endswith(".tsv") else ","
        with open(self.file_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                item_path = (row.get("path") or "").strip()
                item_link = (row.get("link") or "").strip()
                key = item_path or item_link
                if not key:
                    continue
                if key not in item_groups:
                    item_groups[key] = row
                    member_rows_by_item[key] = []
                member_rows_by_item[key].append(row)

        for key, row in item_groups.items():
            item_id = (row.get("id") or "").strip() or key
            item = SharedItem(
                id=item_id,
                name=(row.get("name") or "").strip(),
                path=(row.get("path") or "").strip() or key,
                item_type=(row.get("item_type") or "folder").strip(),
                link=(row.get("link") or None) or None,
                created_at=_parse_expiry(row.get("created_at")),
                updated_at=_parse_expiry(row.get("updated_at")),
                members=[self._build_member(r, csv=True) for r in member_rows_by_item[key]],
            )
            self._add_item(item)

    def _build_member(self, m: dict, csv: bool = False) -> Member:
        if csv:
            name_key = "member_name"
            email_key = "member_email"
            type_key = "member_type"
            perm_key = "permission"
            reshare_key = "can_reshare"
            expiry_key = "expiry"
        else:
            name_key = "name"
            email_key = "email"
            type_key = "member_type"
            perm_key = "permission"
            reshare_key = "can_reshare"
            expiry_key = "expiry"

        email = (m.get(email_key) or "").strip()
        name = (m.get(name_key) or email or "").strip()

        raw_type = (m.get(type_key) or "").strip().lower()
        if not raw_type:
            member_type = self._infer_member_type(email)
        else:
            member_type = _parse_member_type(raw_type)

        return Member(
            name=name,
            email=email,
            member_type=member_type,
            permission=_parse_permission(m.get(perm_key, "view")),
            can_reshare=_parse_bool(m.get(reshare_key, False)),
            expiry=_parse_expiry(m.get(expiry_key)),
        )

    def _infer_member_type(self, email: str) -> MemberType:
        if not email or email.lower() == "anyone":
            return MemberType.ANYONE
        if "@" not in email:
            return MemberType.GROUP
        domain = email.split("@")[-1].lower()
        if self.company_domains and domain not in self.company_domains:
            return MemberType.EXTERNAL
        return MemberType.USER

    def _add_item(self, item: SharedItem):
        if item.path:
            self._items[item.path] = item
            if item.link:
                self._link_index[item.link] = item.path
        elif item.link:
            self._items[item.link] = item
            self._link_index[item.link] = item.link

    def fetch_by_path(self, path: str) -> Optional[SharedItem]:
        return self._items.get(path)

    def fetch_by_link(self, link: str) -> Optional[SharedItem]:
        path = self._link_index.get(link)
        return self._items.get(path) if path else self._items.get(link)

    def fetch_children(self, path: str, recursive: bool = False) -> List[SharedItem]:
        prefix = path.rstrip("/") + "/"
        results = []
        for item_path, item in self._items.items():
            if item_path.startswith(prefix) and item_path != path:
                depth = item_path[len(prefix):].count("/")
                if recursive or depth == 0:
                    results.append(item)
        return results

    @property
    def item_count(self) -> int:
        return len(self._items)
