from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional

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
