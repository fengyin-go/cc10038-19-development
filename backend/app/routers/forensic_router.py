"""跨区域取证交付路由：授权、撤权、签发、数据包准备、重开核对与下载拦截。

通用查询/导出仍走 resource 路由的 /api/forensic_delivery，
这里只承载带业务判断的领域动作，状态流转全部委托给 ForensicDeliveryService。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.forensic_delivery import ForensicDeliveryService

router = APIRouter(prefix="/api/forensic", tags=["跨区域取证"])

service = ForensicDeliveryService()


class CreateRequestPayload(BaseModel):
    subject: str = Field(..., min_length=1)
    regions: list[str] = Field(..., min_length=1)
    scope_note: str = ""
    operator: str = "值班员"


class RegionActionPayload(BaseModel):
    region: str = Field(..., min_length=1)
    authority_ref: str = ""
    reason: str = ""
    operator: str = "区域管理员"


class DownloadPayload(BaseModel):
    credential: str = Field(..., min_length=1)
    regions: list[str] | None = None
    operator: str = "值班员"


def _respond(result: dict[str, Any]) -> dict[str, Any]:
    # 下载类硬拦截需要把 403/409 语义透给前端，其余结果原样返回。
    http_status = result.pop("http_status", None)
    if http_status:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=http_status, content=result)
    return result


@router.post("/requests")
def create_forensic_request(payload: CreateRequestPayload) -> dict[str, Any]:
    result = service.create_request(
        payload.subject, payload.regions,
        scope_note=payload.scope_note, operator=payload.operator,
    )
    return result


@router.post("/requests/{request_id}/authorize")
def authorize_region(request_id: int, payload: RegionActionPayload) -> dict[str, Any]:
    return service.authorize_region(
        request_id, payload.region, payload.authority_ref, operator=payload.operator,
    )


@router.post("/requests/{request_id}/revoke")
def revoke_region(request_id: int, payload: RegionActionPayload) -> dict[str, Any]:
    return service.revoke_region(
        request_id, payload.region, payload.reason, operator=payload.operator,
    )


@router.post("/requests/{request_id}/issue")
def issue_credential(request_id: int) -> dict[str, Any]:
    return service.issue_credential(request_id)


@router.post("/requests/{request_id}/prepare")
def prepare_package(request_id: int) -> dict[str, Any]:
    return service.prepare_package(request_id)


@router.get("/requests/{request_id}/reopen")
def reopen_request(request_id: int) -> dict[str, Any]:
    return service.reopen_request(request_id)


@router.get("/requests/{request_id}/audit")
def list_audit(request_id: int) -> dict[str, Any]:
    return service.list_audit(request_id)


@router.post("/requests/{request_id}/download")
def download_package(request_id: int, payload: DownloadPayload) -> Any:
    result = service.download_package(
        request_id, payload.credential, payload.regions, operator=payload.operator,
    )
    return _respond(result)
