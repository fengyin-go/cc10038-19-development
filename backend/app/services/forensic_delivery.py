"""跨区域日志明细取证交付领域服务。

核心规则：
1. 一份取证申请可覆盖多个采集区域，区域授权可以先后到达，授权状态区分
   待核准 / 已授权 / 已撤回，撤回后值班员仍能读取剩余已授权区域。
2. 取证数据包按来源区域权限裁剪原始日志行，逐行在纳入瞬间复核当时权限，
   共享与撤权并发时只交付能核验当时权限的区域明细。
3. 下载时再次校验签发凭证与实时权限：凭证不能跨申请或扩大区域范围，
   归属不符（含准备期间被撤回）的内容一律拦截并写入访问结论。
4. 采集血缘按授权取证数据包的实际读取范围登记共享结果，访问结论回写。
5. 历史取证中的区域归属引用通过区域别名归一兼容，不要求历史数据迁移。
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable

from app.services.base import BaseModuleService
from app.store import store

# 区域归属状态
GRANT_PENDING = "待核准"
GRANT_AUTHORIZED = "已授权"
GRANT_REVOKED = "已撤回"

# 历史区域归属引用别名表：老取证单里的区域编码统一归一到当前区域标识。
REGION_ALIASES: dict[str, str] = {
    "cn-north-1": "north",
    "north-1": "north",
    "华北": "north",
    "cn-south-1": "south",
    "south-1": "south",
    "华南": "south",
    "cn-east-1": "east",
    "east-1": "east",
    "华东": "east",
}


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _next_id(module: str) -> int:
    return max((int(r.get("id", 0)) for r in store.rows(module)), default=0) + 1


def normalize_region(region: str) -> str:
    """区域编码归一：兼容历史取证中的区域归属引用与别名写法。"""
    raw = str(region or "").strip()
    return REGION_ALIASES.get(raw.casefold(), raw)


class ForensicDeliveryService(BaseModuleService):
    MODULE = "forensic_delivery"
    ENTITY = "取证申请"
    LIST_FIELDS = [
        "取证编号", "申请主题", "涉及区域", "已授权区域", "撤回区域",
        "数据包状态", "签发凭证", "访问结论", "更新时间",
    ]
    REQUIRED_FIELDS = ["申请主题", "涉及区域"]
    STATUS_ORDER = ["待授权", "部分授权", "已签发", "准备中", "部分撤回", "可下载", "已关闭"]
    # 状态流转全部走本服务的专用领域方法，通用动作表故意留空。
    ACTION_RULES: dict[str, str] = {}
    NEGATIVE_ACTIONS: list[str] = []

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    def _audit(
        self,
        request_no: str,
        action: str,
        conclusion: str,
        *,
        region: str = "",
        operator: str = "值班员",
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        entry = {
            "id": _next_id("forensic_audit"),
            "取证编号": request_no,
            "动作": action,
            "区域": region,
            "操作人": operator,
            "时间": _now_iso(),
            "结论": conclusion,
            "详情": json.dumps(detail or {}, ensure_ascii=False),
            "status": "成功" if conclusion != "拦截" else "拦截",
            "pending": False,
            "abnormal": conclusion == "拦截",
        }
        store.rows("forensic_audit").append(entry)
        return entry

    def _grants_of(self, request: dict[str, Any]) -> list[dict[str, Any]]:
        """读取区域授权清单。历史取证单没有授权结构时，按涉及区域字段
        合成「历史归属引用」授权，保证老单据仍可打开核对。"""
        grants = request.get("region_grants")
        if isinstance(grants, list) and grants:
            return grants
        legacy_regions = [
            normalize_region(part)
            for part in str(request.get("涉及区域", "")).replace("，", ",").split(",")
            if part.strip()
        ]
        synthesized: list[dict[str, Any]] = []
        withdrawn = {
            normalize_region(part)
            for part in str(request.get("撤回区域", "")).replace("，", ",").split(",")
            if part.strip()
        }
        for region in legacy_regions:
            synthesized.append({
                "region": region,
                "status": GRANT_REVOKED if region in withdrawn else GRANT_AUTHORIZED,
                "granted_at": request.get("更新时间", _now_iso()),
                "revoked_at": _now_iso() if region in withdrawn else "",
                "grant_version": 1,
                "authority_ref": "历史归属引用",
                "remark": "由历史取证区域归属引用补全",
            })
        request["region_grants"] = synthesized
        return synthesized

    def _find_grant(self, request: dict[str, Any], region: str) -> dict[str, Any] | None:
        target = normalize_region(region)
        for grant in self._grants_of(request):
            if grant["region"] == target:
                return grant
        return None

    def _authorized_regions(self, request: dict[str, Any]) -> list[str]:
        return [g["region"] for g in self._grants_of(request) if g["status"] == GRANT_AUTHORIZED]

    def _refresh_status(self, request: dict[str, Any]) -> None:
        """根据区域授权实时状态与数据包进度刷新取证单状态。"""
        grants = self._grants_of(request)
        authorized = [g for g in grants if g["status"] == GRANT_AUTHORIZED]
        revoked = [g for g in grants if g["status"] == GRANT_REVOKED]
        request["已授权区域"] = ",".join(g["region"] for g in authorized)
        request["撤回区域"] = ",".join(g["region"] for g in revoked)
        request["更新时间"] = _now_iso()

        if not authorized:
            request["status"] = "已关闭"
            request["pending"] = False
            request["abnormal"] = bool(revoked)
            return
        request["abnormal"] = bool(revoked)
        if revoked:
            # 只要存在已撤回区域且仍有可取证区域，就保持部分撤回提示。
            request["status"] = "部分撤回"
            request["pending"] = False
        elif request.get("数据包状态") == "已就绪":
            request["status"] = "可下载"
            request["pending"] = False
        elif request.get("数据包状态") == "准备中":
            request["status"] = "准备中"
            request["pending"] = True
        elif request.get("签发凭证"):
            request["status"] = "已签发"
            request["pending"] = True
        elif len(authorized) < len(grants):
            request["status"] = "部分授权"
            request["pending"] = True
        else:
            request["status"] = "部分授权"
            request["pending"] = True

    def _record_region(self, raw: dict[str, Any]) -> str | None:
        """解析单条原始日志的采集区域归属：原始记录→数据源→批次逐级回退。"""
        explicit = raw.get("region")
        if explicit:
            return normalize_region(str(explicit))
        source_id = raw.get("source_id")
        if source_id:
            for source in store.rows("source_registry"):
                if source.get("来源标识") == source_id:
                    return normalize_region(str(source.get("采集区域", ""))) or None
        batch_no = raw.get("批次编号")
        if batch_no:
            for batch in store.rows("ingest_batch"):
                if batch.get("批次编号") == batch_no:
                    source_id = batch.get("所属数据源")
                    break
            if source_id:
                for source in store.rows("source_registry"):
                    if source.get("来源标识") == source_id:
                        return normalize_region(str(source.get("采集区域", ""))) or None
        return None

    # ------------------------------------------------------------------
    # 阶段1：创建取证申请（含历史区域别名归一）
    # ------------------------------------------------------------------
    def create_request(
        self,
        subject: str,
        regions: list[str],
        *,
        scope_note: str = "",
        operator: str = "值班员",
    ) -> dict[str, Any]:
        subject = str(subject or "").strip()
        if not subject:
            return {"ok": False, "message": "申请主题不能为空"}
        normalized: list[str] = []
        alias_trace: dict[str, str] = {}
        for raw_region in regions or []:
            raw_name = str(raw_region or "").strip()
            if not raw_name:
                continue
            canon = normalize_region(raw_name)
            alias_trace[raw_name] = canon
            if canon not in normalized:
                normalized.append(canon)
        if not normalized:
            return {"ok": False, "message": "至少需要一个取证区域"}

        new_id = max((int(r.get("id", 0)) for r in store.rows(self.MODULE)), default=0) + 1
        request_no = f"FREQ-{new_id:04d}"
        grants = [
            {
                "region": region,
                "status": GRANT_PENDING,
                "granted_at": "",
                "revoked_at": "",
                "grant_version": 0,
                "authority_ref": "",
                "remark": "",
            }
            for region in normalized
        ]
        entry = {
            "id": new_id,
            "取证编号": request_no,
            "申请主题": subject,
            "涉及区域": ",".join(normalized),
            "已授权区域": "",
            "撤回区域": "",
            "数据包状态": "未准备",
            "签发凭证": "",
            "访问结论": "尚未下载",
            "更新时间": _now_iso(),
            "status": "待授权",
            "pending": True,
            "abnormal": False,
            "scope_note": scope_note,
            "region_grants": grants,
            "区域别名映射": json.dumps(alias_trace, ensure_ascii=False),
            "package": None,
        }
        store.rows(self.MODULE).append(entry)
        self._audit(request_no, "创建申请", "已登记", detail={
            "regions": normalized, "alias_trace": alias_trace, "scope_note": scope_note,
        }, operator=operator)
        return {"ok": True, "message": f"取证申请 {request_no} 已登记", "entry": entry}

    # ------------------------------------------------------------------
    # 阶段2：区域授权（支持两个区域先后授权）
    # ------------------------------------------------------------------
    def authorize_region(
        self,
        request_id: int,
        region: str,
        authority_ref: str,
        *,
        operator: str = "区域管理员",
    ) -> dict[str, Any]:
        request = store.find(self.MODULE, request_id)
        if request is None:
            return {"ok": False, "message": f"取证申请 {request_id} 不存在"}
        grant = self._find_grant(request, region)
        if grant is None:
            return {"ok": False, "message": f"区域 {region} 不在取证申请 {request['取证编号']} 范围内"}
        canon = grant["region"]
        if grant["status"] == GRANT_REVOKED:
            return {"ok": False, "message": f"区域 {canon} 的共享已撤回，不能重新授权，请新建取证申请"}
        grant["status"] = GRANT_AUTHORIZED
        grant["granted_at"] = _now_iso()
        grant["grant_version"] = int(grant.get("grant_version", 0)) + 1
        grant["authority_ref"] = authority_ref or f"auth-{canon}-{grant['grant_version']}"
        grant["remark"] = ""
        self._refresh_status(request)
        self._audit(request["取证编号"], "区域授权", "已授权", region=canon,
                    operator=operator, detail={"authority_ref": grant["authority_ref"],
                                               "grant_version": grant["grant_version"]})
        return {"ok": True, "message": f"区域 {canon} 已授权共享", "entry": request}

    # ------------------------------------------------------------------
    # 阶段3：撤权（签发后、准备中、就绪后均可撤回）
    # ------------------------------------------------------------------
    def revoke_region(
        self,
        request_id: int,
        region: str,
        reason: str,
        *,
        operator: str = "区域管理员",
    ) -> dict[str, Any]:
        request = store.find(self.MODULE, request_id)
        if request is None:
            return {"ok": False, "message": f"取证申请 {request_id} 不存在"}
        grant = self._find_grant(request, region)
        if grant is None:
            return {"ok": False, "message": f"区域 {region} 不在取证申请 {request['取证编号']} 范围内"}
        canon = grant["region"]
        if grant["status"] == GRANT_REVOKED:
            return {"ok": False, "message": f"区域 {canon} 已是撤回状态"}
        previous = grant["status"]
        grant["status"] = GRANT_REVOKED
        grant["revoked_at"] = _now_iso()
        grant["remark"] = reason or "区域撤回共享"
        during_prepare = request.get("数据包状态") in ("准备中", "已就绪")
        self._refresh_status(request)
        self._audit(
            request["取证编号"],
            "准备期间撤回" if during_prepare else "撤回共享",
            "已撤回",
            region=canon,
            operator=operator,
            detail={
                "reason": grant["remark"],
                "previous_status": previous,
                "during_package_prepare": during_prepare,
                "remaining_authorized": self._authorized_regions(request),
            },
        )
        return {"ok": True, "message": f"区域 {canon} 已撤回共享，剩余授权区域："
                f"{'、'.join(self._authorized_regions(request)) or '无'}", "entry": request}

    # ------------------------------------------------------------------
    # 阶段4：签发下载凭证（凭证绑定申请与授权区域，不能扩大权限）
    # ------------------------------------------------------------------
    def issue_credential(self, request_id: int) -> dict[str, Any]:
        request = store.find(self.MODULE, request_id)
        if request is None:
            return {"ok": False, "message": f"取证申请 {request_id} 不存在"}
        authorized = self._authorized_regions(request)
        if not authorized:
            return {"ok": False, "message": "尚无已授权区域，不能签发取证凭证"}
        if request.get("签发凭证"):
            return {"ok": False, "message": "凭证已签发，不能重复签发", "entry": request}
        scope_digest = hashlib.sha256(
            json.dumps(authorized, sort_keys=True).encode()
        ).hexdigest()[:10]
        credential = f"cred-{request['取证编号']}-{scope_digest}"
        request["签发凭证"] = credential
        request["credential_scope"] = list(authorized)
        self._refresh_status(request)
        self._audit(request["取证编号"], "签发凭证", "已签发",
                    detail={"credential": credential, "scope": authorized})
        return {"ok": True, "message": f"取证凭证已签发，授权范围：{'、'.join(authorized)}",
                "entry": request, "credential": credential}

    # ------------------------------------------------------------------
    # 阶段5：准备授权取证数据包（逐行核验当时权限，按区域裁剪原始行）
    # ------------------------------------------------------------------
    def prepare_package(
        self,
        request_id: int,
        *,
        row_verify_hook: Callable[["ForensicDeliveryService", dict[str, Any], str], None] | None = None,
    ) -> dict[str, Any]:
        request = store.find(self.MODULE, request_id)
        if request is None:
            return {"ok": False, "message": f"取证申请 {request_id} 不存在"}
        if not request.get("签发凭证"):
            return {"ok": False, "message": "尚未签发取证凭证，不能准备数据包"}
        if not self._authorized_regions(request):
            return {"ok": False, "message": "授权区域均已撤回，无可取证内容"}

        request["数据包状态"] = "准备中"
        request["status"] = "准备中"
        request["更新时间"] = _now_iso()
        prepare_started_at = _now_iso()
        verified_regions: set[str] = set()

        included: list[dict[str, Any]] = []
        excluded: list[dict[str, Any]] = []
        read_scope: dict[str, dict[str, Any]] = {}

        for raw in store.rows("raw_records"):
            region = self._record_region(raw)
            if region is None:
                excluded.append({
                    "record_id": raw.get("id"), "region": "",
                    "reason": "归属不明：无法解析采集区域",
                })
                continue
            # 每个区域在首次纳入前留并发接缝：测试可在此时撤权，
            # 模拟文件准备期间共享/撤权并发，随后的逐行核验以实时权限为准。
            if region not in verified_regions:
                verified_regions.add(region)
                if row_verify_hook is not None:
                    row_verify_hook(self, request, region)

            grant = self._find_grant(request, region)
            if grant is None:
                excluded.append({"record_id": raw.get("id"), "region": region,
                                 "reason": "归属不符：区域不在取证申请范围"})
                continue
            if grant["status"] == GRANT_PENDING:
                excluded.append({"record_id": raw.get("id"), "region": region,
                                 "reason": "尚未核准：区域共享授权待审批"})
                continue
            if grant["status"] == GRANT_REVOKED:
                excluded.append({"record_id": raw.get("id"), "region": region,
                                 "reason": "授权已撤回：准备期间权限失效"})
                continue

            verified_at = _now_iso()
            body = str(raw.get("原始正文", ""))
            content_digest = hashlib.sha256(body.encode()).hexdigest()[:16]
            field_attribution = {
                field: region for field in ("批次编号", "原始行号", "采集时间戳", "原始正文")
            }
            included.append({
                "record_id": raw.get("id"),
                "batch_no": raw.get("批次编号"),
                "line_no": raw.get("原始行号"),
                "region": region,
                "raw_body": body,
                "field_attribution": field_attribution,
                "grant_version": grant["grant_version"],
                "authority_ref": grant.get("authority_ref", ""),
                "verified_at": verified_at,
                "content_digest": content_digest,
            })
            scope = read_scope.setdefault(region, {
                "region": region, "grant_version": grant["grant_version"],
                "authority_ref": grant.get("authority_ref", ""),
                "verified_at": verified_at, "record_ids": [], "row_count": 0,
            })
            scope["record_ids"].append(raw.get("id"))
            scope["row_count"] += 1

        package_no = f"FP-{_next_id('data_export'):04d}"
        manifest = {
            "package_no": package_no,
            "request_no": request["取证编号"],
            "prepared_at": _now_iso(),
            "prepare_started_at": prepare_started_at,
            "credential": request["签发凭证"],
            "grant_scope": request.get("credential_scope", self._authorized_regions(request)),
            "authorized_regions": self._authorized_regions(request),
            "included_count": len(included),
            "excluded_count": len(excluded),
            "included_digests": [row["content_digest"] for row in included],
        }
        manifest["package_digest"] = hashlib.sha256(
            json.dumps(manifest, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()[:16]

        package = {
            "package_no": package_no,
            "manifest": manifest,
            "rows": included,
            "blocked": excluded,
        }
        request["package"] = package
        request["数据包状态"] = "已就绪"
        self._refresh_status(request)

        self._register_lineage(request, list(read_scope.values()), manifest)
        self._audit(request["取证编号"], "准备数据包", "已就绪", detail={
            "package_no": package_no,
            "included": len(included),
            "excluded": len(excluded),
            "regions": list(read_scope.keys()),
        })
        return {"ok": True, "message": f"授权取证数据包 {package_no} 已就绪",
                "entry": request, "package": package}

    # ------------------------------------------------------------------
    # 采集血缘：按数据包实际读取范围登记共享结果
    # ------------------------------------------------------------------
    def _register_lineage(
        self,
        request: dict[str, Any],
        read_scope: list[dict[str, Any]],
        manifest: dict[str, Any],
    ) -> dict[str, Any]:
        lineages = store.rows("data_lineage")
        existing = None
        for row in lineages:
            if row.get("取证编号") == request["取证编号"]:
                existing = row
                break
        scope_payload = json.dumps(read_scope, ensure_ascii=False)
        if existing is not None:
            existing["实际读取范围"] = scope_payload
            existing["记录时间"] = _now_iso()
            existing["package_no"] = manifest["package_no"]
            return existing
        entry = {
            "id": _next_id("data_lineage"),
            "来源批次": f"授权取证数据包 {manifest['package_no']}",
            "解析规则版本": f"取证授权-{request['取证编号']}",
            "标准化版本": "授权取证裁剪明细v1",
            "下游消费标识": f"forensic-{request['取证编号']}",
            "记录时间": _now_iso(),
            "status": "已记录",
            "pending": False,
            "abnormal": False,
            "取证编号": request["取证编号"],
            "package_no": manifest["package_no"],
            "实际读取范围": scope_payload,
            "访问结论": "待下载",
        }
        lineages.append(entry)
        return entry

    # ------------------------------------------------------------------
    # 阶段6：重新打开取证入口，查看剩余可取证范围与撤回/待核准区分
    # ------------------------------------------------------------------
    def reopen_request(self, request_id: int) -> dict[str, Any]:
        request = store.find(self.MODULE, request_id)
        if request is None:
            return {"ok": False, "message": f"取证申请 {request_id} 不存在"}
        grants = self._grants_of(request)
        authorized = self._authorized_regions(request)
        readable_records = 0
        for raw in store.rows("raw_records"):
            region = self._record_region(raw)
            if region and region in authorized:
                readable_records += 1
        package = request.get("package")
        return {
            "ok": True,
            "entry": request,
            "grants": grants,
            "readable_regions": authorized,
            "pending_regions": [g["region"] for g in grants if g["status"] == GRANT_PENDING],
            "revoked_regions": [g["region"] for g in grants if g["status"] == GRANT_REVOKED],
            "readable_record_count": readable_records,
            "package_ready": request.get("数据包状态") == "已就绪",
            "package_summary": (
                {
                    "package_no": package["package_no"],
                    "included": len(package["rows"]),
                    "blocked": len(package["blocked"]),
                    "manifest": package["manifest"],
                }
                if package else None
            ),
            "audit": [a for a in store.rows("forensic_audit")
                      if a.get("取证编号") == request["取证编号"]],
        }

    def list_audit(self, request_id: int) -> dict[str, Any]:
        request = store.find(self.MODULE, request_id)
        if request is None:
            return {"ok": False, "message": f"取证申请 {request_id} 不存在"}
        entries = [a for a in store.rows("forensic_audit")
                   if a.get("取证编号") == request["取证编号"]]
        return {"ok": True, "request_no": request["取证编号"], "items": entries}

    # ------------------------------------------------------------------
    # 阶段7：下载交付，拦截归属不符内容，凭证不得扩大权限
    # ------------------------------------------------------------------
    def download_package(
        self,
        request_id: int,
        credential: str,
        submitted_regions: list[str] | None = None,
        *,
        operator: str = "值班员",
    ) -> dict[str, Any]:
        request = store.find(self.MODULE, request_id)
        if request is None:
            return {"ok": False, "blocked": True, "message": f"取证申请 {request_id} 不存在"}
        request_no = request["取证编号"]

        # 校验1：凭证必须是本申请签发的凭证
        if not credential or credential != request.get("签发凭证"):
            self._audit(request_no, "下载交付", "拦截", operator=operator,
                        detail={"reason": "凭证无效或不属于本申请", "submitted_credential": credential})
            return {"ok": False, "blocked": True, "http_status": 403,
                    "message": "取证凭证无效或不属于本申请，下载已拦截"}

        package = request.get("package")
        if not package or request.get("数据包状态") != "已就绪":
            return {"ok": False, "blocked": True, "http_status": 409,
                    "message": "取证数据包尚未就绪，请先准备数据包"}

        # 校验2：跨区域提交凭证不能扩大权限——提交区域必须落在凭证授权范围内
        requested = {normalize_region(r) for r in (submitted_regions or []) if str(r).strip()}
        live_authorized = set(self._authorized_regions(request))
        credential_scope = set(request.get("credential_scope") or live_authorized)
        overflow = requested - credential_scope
        if overflow:
            self._audit(request_no, "下载交付", "拦截", operator=operator, detail={
                "reason": "凭证区域越权", "submitted_regions": sorted(requested),
                "credential_scope": sorted(credential_scope),
            })
            return {"ok": False, "blocked": True, "http_status": 403,
                    "message": f"凭证不能扩大权限，越权区域：{'、'.join(sorted(overflow))}，下载已拦截"}

        # 校验3：逐行复核实时区域归属，准备后被撤回的内容一律拦截
        delivered: list[dict[str, Any]] = []
        blocked_rows: list[dict[str, Any]] = []
        effective_regions = requested or live_authorized
        for row in package["rows"]:
            region = row["region"]
            if requested and region not in requested:
                blocked_rows.append({"record_id": row["record_id"], "region": region,
                                     "reason": "不在本次提交的凭证区域范围内"})
                continue
            grant = self._find_grant(request, region)
            if grant is None or grant["status"] != GRANT_AUTHORIZED:
                blocked_rows.append({
                    "record_id": row["record_id"], "region": region,
                    "reason": "下载时归属不符：区域授权已撤回或失效",
                })
                continue
            delivered.append(row)

        conclusion = {
            "downloaded_at": _now_iso(),
            "operator": operator,
            "delivered_count": len(delivered),
            "blocked_count": len(blocked_rows),
            "delivered_regions": sorted({r["region"] for r in delivered}),
            "blocked": blocked_rows,
            "credential_scope": sorted(credential_scope),
        }
        conclusion_text = f"放行{len(delivered)}行/拦截{len(blocked_rows)}行"
        request["访问结论"] = conclusion_text
        request["访问结论明细"] = json.dumps(conclusion, ensure_ascii=False)
        request["更新时间"] = _now_iso()

        # 访问结论回写采集血缘
        for lineage in store.rows("data_lineage"):
            if lineage.get("取证编号") == request_no:
                lineage["访问结论"] = conclusion_text
                lineage["访问结论明细"] = request["访问结论明细"]
                lineage["记录时间"] = _now_iso()

        self._audit(request_no, "下载交付",
                    "拦截" if blocked_rows and not delivered else "成功",
                    operator=operator, detail=conclusion)
        return {
            "ok": bool(delivered),
            "blocked": False,
            "message": conclusion_text if delivered else "全部内容归属不符，下载被拦截",
            "package_no": package["package_no"],
            "manifest": package["manifest"],
            "delivered": delivered,
            "blocked_rows": blocked_rows,
            "conclusion": conclusion,
        }
