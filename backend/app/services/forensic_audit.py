"""取证审计条目领域服务：只提供只读清单与统计，写入由取证服务统一完成。"""
from __future__ import annotations

from app.services.base import BaseModuleService


class ForensicAuditService(BaseModuleService):
    MODULE = "forensic_audit"
    ENTITY = "取证审计"
    LIST_FIELDS = ["取证编号", "动作", "区域", "操作人", "时间", "结论"]
    REQUIRED_FIELDS: list[str] = []
    STATUS_ORDER = ["成功", "拦截"]
    ACTION_RULES: dict[str, str] = {}
    NEGATIVE_ACTIONS: list[str] = []
