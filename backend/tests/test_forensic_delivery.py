"""跨区域日志明细取证交付测试。

验收主线：用两个区域（north / south）的日志发起共享取证，在文件准备期间
撤回其中一个区域的授权，重新打开取证入口，确认仍可读取已授权区域明细，
并核对撤回记录与审计条目；同时覆盖凭证越权、下载拦截、血缘回写与
历史区域归属引用兼容。
"""
from __future__ import annotations

import pytest

from app.services.forensic_delivery import (
    GRANT_AUTHORIZED,
    GRANT_PENDING,
    GRANT_REVOKED,
    ForensicDeliveryService,
    normalize_region,
)
from app.store import store


NORTH_LOGS = [
    {"body": "2026-11-20T08:00:00|INFO|north login ok"},
    {"body": "2026-11-20T08:05:00|WARN|north cpu high"},
    {"body": "2026-11-20T08:10:00|ERROR|north disk fail"},
]
SOUTH_LOGS = [
    {"body": "2026-11-20T09:00:00|INFO|south gateway start"},
    {"body": "2026-11-20T09:05:00|ERROR|south timeout"},
]


@pytest.fixture
def forensic():
    return ForensicDeliveryService()


def _ingest_two_region_logs(pipeline):
    """准备 north、south 两个区域各一批已采集原始日志。"""
    pipeline.register_source("src-north", "http", "north")
    pipeline.validate_source("src-north")
    north_batch = pipeline.start_ingest_batch("src-north", "2026-11-20T08", NORTH_LOGS)
    pipeline.register_source("src-south", "http", "south")
    pipeline.validate_source("src-south")
    south_batch = pipeline.start_ingest_batch("src-south", "2026-11-20T09", SOUTH_LOGS)
    return north_batch["batch"]["批次编号"], south_batch["batch"]["批次编号"]


class TestRegionNormalization:
    """区域别名归一：兼容历史取证中的区域归属引用。"""

    def test_alias_maps_to_canonical(self):
        assert normalize_region("cn-north-1") == "north"
        assert normalize_region("华南") == "south"
        assert normalize_region("EAST-1") == "east"

    def test_unknown_region_kept_as_is(self):
        assert normalize_region("west-9") == "west-9"
        assert normalize_region("") == ""

    def test_create_request_normalizes_regions(self, forensic):
        result = forensic.create_request("别名取证", ["cn-north-1", "华南", "north"])
        assert result["ok"] is True
        entry = result["entry"]
        assert entry["涉及区域"] == "north,south"
        grants = {g["region"]: g["status"] for g in entry["region_grants"]}
        assert grants == {"north": GRANT_PENDING, "south": GRANT_PENDING}

    def test_create_request_requires_region(self, forensic):
        result = forensic.create_request("空区域", [])
        assert result["ok"] is False
        result2 = forensic.create_request("", ["north"])
        assert result2["ok"] is False


class TestGrantAndRevoke:
    """区域先后授权、撤权与三种权限状态区分。"""

    def test_two_regions_authorize_sequentially(self, pipeline, forensic):
        _ingest_two_region_logs(pipeline)
        req = forensic.create_request("双区域取证", ["north", "south"])["entry"]
        rid = req["id"]

        first = forensic.authorize_region(rid, "north", "auth-n-1")
        assert first["ok"] is True
        assert first["entry"]["status"] == "部分授权"
        assert forensic.reopen_request(rid)["readable_regions"] == ["north"]

        second = forensic.authorize_region(rid, "south", "auth-s-1")
        assert second["ok"] is True
        snapshot = forensic.reopen_request(rid)
        assert sorted(snapshot["readable_regions"]) == ["north", "south"]
        assert snapshot["pending_regions"] == []

    def test_authorize_region_out_of_scope_rejected(self, pipeline, forensic):
        _ingest_two_region_logs(pipeline)
        req = forensic.create_request("范围外授权", ["north"])["entry"]
        result = forensic.authorize_region(req["id"], "south", "auth-x")
        assert result["ok"] is False
        assert "不在取证申请" in result["message"]

    def test_revoke_after_issue_keeps_remaining_region(self, pipeline, forensic):
        _ingest_two_region_logs(pipeline)
        req = forensic.create_request("签发后撤权", ["north", "south"])["entry"]
        rid = req["id"]
        forensic.authorize_region(rid, "north", "auth-n-1")
        forensic.authorize_region(rid, "south", "auth-s-1")
        forensic.issue_credential(rid)

        result = forensic.revoke_region(rid, "south", "区域共享审批到期")
        assert result["ok"] is True
        snapshot = forensic.reopen_request(rid)
        # 值班员能明确区分已撤回与尚未核准，且知道剩余可取证区域
        assert snapshot["readable_regions"] == ["north"]
        assert snapshot["revoked_regions"] == ["south"]
        assert snapshot["pending_regions"] == []
        assert snapshot["entry"]["status"] == "部分撤回"
        assert snapshot["readable_record_count"] == len(NORTH_LOGS)

    def test_revoked_region_cannot_be_reauthorized(self, pipeline, forensic):
        _ingest_two_region_logs(pipeline)
        req = forensic.create_request("撤回不可恢复", ["north", "south"])["entry"]
        rid = req["id"]
        forensic.authorize_region(rid, "south", "auth-s-1")
        forensic.revoke_region(rid, "south", "临时撤回")
        again = forensic.authorize_region(rid, "south", "auth-s-2")
        assert again["ok"] is False
        assert "不能重新授权" in again["message"]

    def test_revoke_all_regions_closes_request(self, pipeline, forensic):
        _ingest_two_region_logs(pipeline)
        req = forensic.create_request("全部撤回", ["north"])["entry"]
        rid = req["id"]
        forensic.authorize_region(rid, "north", "auth-n-1")
        forensic.revoke_region(rid, "north", "整体撤回")
        snapshot = forensic.reopen_request(rid)
        assert snapshot["readable_regions"] == []
        assert snapshot["entry"]["status"] == "已关闭"


class TestPackagePreparation:
    """授权取证数据包：按来源权限裁剪原始行，并发撤权只交付当时可核验区域。"""

    def test_prepare_requires_credential(self, pipeline, forensic):
        _ingest_two_region_logs(pipeline)
        req = forensic.create_request("未签发", ["north"])["entry"]
        forensic.authorize_region(req["id"], "north", "auth-n-1")
        result = forensic.prepare_package(req["id"])
        assert result["ok"] is False
        assert "签发取证凭证" in result["message"]

    def test_pending_region_rows_excluded(self, pipeline, forensic):
        _ingest_two_region_logs(pipeline)
        req = forensic.create_request("待核准裁剪", ["north", "south"])["entry"]
        rid = req["id"]
        forensic.authorize_region(rid, "north", "auth-n-1")  # south 保持待核准
        forensic.issue_credential(rid)
        result = forensic.prepare_package(rid)
        assert result["ok"] is True
        package = result["package"]
        included_regions = {row["region"] for row in package["rows"]}
        assert included_regions == {"north"}
        assert len(package["rows"]) == len(NORTH_LOGS)
        pending_blocked = [b for b in package["blocked"] if "尚未核准" in b["reason"]]
        assert len(pending_blocked) == len(SOUTH_LOGS)

    def test_concurrent_revoke_during_prepare_delivers_only_authorized(self, pipeline, forensic):
        """文件准备期间撤回 south：逐行核验实时权限，south 全部拦截、north 全量交付。"""
        _ingest_two_region_logs(pipeline)
        req = forensic.create_request("准备期撤权", ["north", "south"])["entry"]
        rid = req["id"]
        forensic.authorize_region(rid, "north", "auth-n-1")
        forensic.authorize_region(rid, "south", "auth-s-1")
        forensic.issue_credential(rid)

        def revoke_south_on_first_touch(svc, request, region):
            if region == "south":
                svc.revoke_region(request["id"], "south", "准备期间区域撤回共享")

        result = forensic.prepare_package(rid, row_verify_hook=revoke_south_on_first_touch)
        assert result["ok"] is True
        package = result["package"]
        assert [row["region"] for row in package["rows"]] == ["north"] * len(NORTH_LOGS)
        revoked_blocked = [b for b in package["blocked"] if "授权已撤回" in b["reason"]]
        assert len(revoked_blocked) == len(SOUTH_LOGS)
        # 每行带区域归属与字段级归属，方便核对每个字段的区域归属
        first = package["rows"][0]
        assert first["field_attribution"]["原始正文"] == "north"
        assert first["authority_ref"] == "auth-n-1"

    def test_out_of_scope_and_unknown_attribution_blocked(self, pipeline, forensic):
        _ingest_two_region_logs(pipeline)
        # 再登记一个 east 区域数据源并采集，取证申请不包含 east
        pipeline.register_source("src-east", "http", "east")
        pipeline.validate_source("src-east")
        pipeline.start_ingest_batch("src-east", "2026-11-20T10", [
            {"body": "2026-11-20T10:00:00|INFO|east internal"},
        ])
        req = forensic.create_request("归属不符拦截", ["north", "south"])["entry"]
        rid = req["id"]
        forensic.authorize_region(rid, "north", "auth-n-1")
        forensic.authorize_region(rid, "south", "auth-s-1")
        forensic.issue_credential(rid)
        package = forensic.prepare_package(rid)["package"]
        east_blocked = [b for b in package["blocked"] if b["region"] == "east"]
        assert east_blocked and "不在取证申请范围" in east_blocked[0]["reason"]
        # 种子数据中无来源归属的历史日志归为归属不明
        unknown = [b for b in package["blocked"] if b["region"] == ""]
        assert unknown and "归属不明" in unknown[0]["reason"]

    def test_lineage_registered_with_actual_read_scope(self, pipeline, forensic):
        _ingest_two_region_logs(pipeline)
        req = forensic.create_request("血缘登记", ["north", "south"])["entry"]
        rid = req["id"]
        forensic.authorize_region(rid, "north", "auth-n-1")
        forensic.authorize_region(rid, "south", "auth-s-1")
        forensic.issue_credential(rid)
        forensic.prepare_package(rid)

        import json
        lineages = [row for row in store.rows("data_lineage")
                    if row.get("取证编号") == req["取证编号"]]
        assert len(lineages) == 1
        scope = json.loads(lineages[0]["实际读取范围"])
        regions = {item["region"]: item["row_count"] for item in scope}
        assert regions == {"north": len(NORTH_LOGS), "south": len(SOUTH_LOGS)}
        assert lineages[0]["访问结论"] == "待下载"


class TestDownloadEnforcement:
    """下载拦截：凭证不可扩大权限，归属不符内容拦截，结论回写。"""

    def _issued_two_region_request(self, pipeline, forensic):
        _ingest_two_region_logs(pipeline)
        req = forensic.create_request("下载管控", ["north", "south"])["entry"]
        rid = req["id"]
        forensic.authorize_region(rid, "north", "auth-n-1")
        forensic.authorize_region(rid, "south", "auth-s-1")
        issue = forensic.issue_credential(rid)
        forensic.prepare_package(rid)
        return rid, issue["credential"]

    def test_download_with_wrong_credential_blocked(self, pipeline, forensic):
        rid, credential = self._issued_two_region_request(pipeline, forensic)
        result = forensic.download_package(rid, "cred-forged-9999")
        assert result["ok"] is False
        assert result["blocked"] is True
        assert result["http_status"] == 403
        audit = forensic.list_audit(rid)["items"]
        assert any(a["结论"] == "拦截" and a["动作"] == "下载交付" for a in audit)

    def test_submitted_regions_cannot_expand_credential_scope(self, pipeline, forensic):
        rid, credential = self._issued_two_region_request(pipeline, forensic)
        # 凭证只覆盖 north/south，提交 east 属于跨区域扩大权限
        result = forensic.download_package(rid, credential, ["north", "east"])
        assert result["ok"] is False
        assert result["http_status"] == 403
        assert "凭证不能扩大权限" in result["message"]

    def test_revoke_between_prepare_and_download_blocks_rows(self, pipeline, forensic):
        """签发后到实际下载之间撤回 south：下载时逐行复核，south 拦截、north 放行。"""
        rid, credential = self._issued_two_region_request(pipeline, forensic)
        forensic.revoke_region(rid, "south", "下载前撤回共享")

        result = forensic.download_package(rid, credential)
        assert result["ok"] is True
        assert len(result["delivered"]) == len(NORTH_LOGS)
        assert {row["region"] for row in result["delivered"]} == {"north"}
        assert len(result["blocked_rows"]) == len(SOUTH_LOGS)
        assert all("已撤回" in row["reason"] for row in result["blocked_rows"])

        # 访问结论回写取证清单与采集血缘
        entry = store.find("forensic_delivery", rid)
        assert f"放行{len(NORTH_LOGS)}行" in entry["访问结论"]
        lineage = [r for r in store.rows("data_lineage")
                   if r.get("取证编号") == entry["取证编号"]][0]
        assert lineage["访问结论"] == entry["访问结论"]
        assert "blocked_count" in lineage["访问结论明细"]

    def test_reopen_after_revoke_allows_continue_authorized_read(self, pipeline, forensic):
        """验收主线：重新打开取证入口，仍可继续读取已授权区域明细。"""
        rid, credential = self._issued_two_region_request(pipeline, forensic)

        def revoke_south(svc, request, region):
            if region == "south":
                svc.revoke_region(request["id"], "south", "准备期撤回")
        forensic.prepare_package(rid, row_verify_hook=revoke_south)

        snapshot = forensic.reopen_request(rid)
        assert snapshot["readable_regions"] == ["north"]
        assert snapshot["revoked_regions"] == ["south"]
        assert snapshot["package_ready"] is True
        assert snapshot["package_summary"]["included"] == len(NORTH_LOGS)

        download = forensic.download_package(rid, credential)
        assert download["ok"] is True
        assert len(download["delivered"]) == len(NORTH_LOGS)

        # 撤回记录与审计条目齐全
        audit = forensic.list_audit(rid)["items"]
        actions = [(a["动作"], a["区域"], a["结论"]) for a in audit]
        assert ("准备期间撤回", "south", "已撤回") in actions
        assert ("区域授权", "north", "已授权") in actions
        assert ("准备数据包", "", "已就绪") in actions

    def test_all_revoked_download_is_fully_blocked(self, pipeline, forensic):
        rid, credential = self._issued_two_region_request(pipeline, forensic)
        forensic.revoke_region(rid, "north", "全撤")
        forensic.revoke_region(rid, "south", "全撤")
        result = forensic.download_package(rid, credential)
        assert result["ok"] is False
        assert len(result["delivered"]) == 0
        assert len(result["blocked_rows"]) == len(NORTH_LOGS) + len(SOUTH_LOGS)


class TestLegacyCompatibility:
    """兼容历史取证中的区域归属引用。"""

    def test_legacy_request_grants_synthesized(self, forensic):
        # 种子数据 id=1 是没有 region_grants 结构的历史取证单
        snapshot = forensic.reopen_request(1)
        assert snapshot["ok"] is True
        grants = {g["region"]: g["status"] for g in snapshot["grants"]}
        assert grants == {"north": GRANT_AUTHORIZED, "south": GRANT_REVOKED}
        assert snapshot["readable_regions"] == ["north"]
        assert snapshot["revoked_regions"] == ["south"]

    def test_legacy_request_visible_in_generic_list(self):
        rows = store.rows("forensic_delivery")
        legacy = [r for r in rows if r["取证编号"] == "FREQ-LEGACY-01"]
        assert len(legacy) == 1
        assert legacy[0]["status"] == "部分撤回"


class TestAuditTrail:
    """审计条目完整记录授权、撤回、准备、下载拦截。"""

    def test_full_story_audit_chain(self, pipeline, forensic):
        _ingest_two_region_logs(pipeline)
        req = forensic.create_request("审计链路", ["cn-north-1", "cn-south-1"])["entry"]
        rid = req["id"]
        forensic.authorize_region(rid, "north", "auth-n-1")
        forensic.authorize_region(rid, "south", "auth-s-1")
        credential = forensic.issue_credential(rid)["credential"]
        forensic.prepare_package(rid, row_verify_hook=lambda svc, r, region: (
            svc.revoke_region(r["id"], "south", "并发撤回") if region == "south" else None
        ))
        forensic.download_package(rid, credential)

        audit = store.rows("forensic_audit")
        chain = [a for a in audit if a["取证编号"] == req["取证编号"]]
        action_sequence = [a["动作"] for a in chain]
        assert action_sequence == [
            "创建申请", "区域授权", "区域授权", "签发凭证",
            "准备期间撤回", "准备数据包", "下载交付",
        ]
        # 审计模块可通过通用资源接口查询
        assert all(a["取证编号"] for a in audit)
        blocked_audit = [a for a in chain if a["结论"] == "拦截"]
        # 本次下载 north 全放行，无拦截条目；撤权单独成链
        assert all(a["区域"] in ("north", "south", "") for a in chain)
