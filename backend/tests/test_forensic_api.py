"""跨区域取证交付的 HTTP 端到端测试：走真实 FastAPI 路由，
验证路由分派、403 拦截语义与通用资源接口对取证模块的可见性。
"""
from __future__ import annotations

import pytest

from fastapi.testclient import TestClient

from app.main import app
from app.services.pipeline import pipeline
from app.store import store


@pytest.fixture
def client():
    return TestClient(app)


def _seed_two_region_data():
    pipeline.register_source("web-north", "http", "north")
    pipeline.validate_source("web-north")
    pipeline.start_ingest_batch("web-north", "2026-11-20T08", [
        {"body": "2026-11-20T08:00:00|INFO|north-a"},
        {"body": "2026-11-20T08:01:00|INFO|north-b"},
    ])
    pipeline.register_source("web-south", "http", "south")
    pipeline.validate_source("web-south")
    pipeline.start_ingest_batch("web-south", "2026-11-20T09", [
        {"body": "2026-11-20T09:00:00|INFO|south-a"},
    ])


class TestForensicApi:
    def test_full_forensic_flow_over_http(self, client):
        _seed_two_region_data()

        created = client.post("/api/forensic/requests", json={
            "subject": "HTTP 端到端取证",
            "regions": ["cn-north-1", "cn-south-1"],
        })
        assert created.status_code == 200
        body = created.json()
        assert body["ok"] is True
        rid = body["entry"]["id"]
        assert body["entry"]["涉及区域"] == "north,south"

        # 两区域先后授权
        assert client.post(f"/api/forensic/requests/{rid}/authorize",
                           json={"region": "north", "authority_ref": "a-n"}).json()["ok"]
        assert client.post(f"/api/forensic/requests/{rid}/authorize",
                           json={"region": "south", "authority_ref": "a-s"}).json()["ok"]

        issued = client.post(f"/api/forensic/requests/{rid}/issue").json()
        credential = issued["credential"]

        prepared = client.post(f"/api/forensic/requests/{rid}/prepare").json()
        assert prepared["package"]["manifest"]["included_count"] == 3

        # 通用资源接口能列出取证清单
        listed = client.get("/api/forensic_delivery").json()
        assert listed["total"] >= 2
        assert any(item["取证编号"] == body["entry"]["取证编号"] for item in listed["items"])

        # 下载前撤回 south
        revoke = client.post(f"/api/forensic/requests/{rid}/revoke",
                             json={"region": "south", "reason": "HTTP 撤权"})
        assert revoke.json()["ok"] is True

        # 重开入口：只剩 north 可读
        reopen = client.get(f"/api/forensic/requests/{rid}/reopen").json()
        assert reopen["readable_regions"] == ["north"]
        assert reopen["revoked_regions"] == ["south"]

        download = client.post(f"/api/forensic/requests/{rid}/download",
                               json={"credential": credential})
        assert download.status_code == 200
        payload = download.json()
        assert len(payload["delivered"]) == 2
        assert len(payload["blocked_rows"]) == 1
        assert payload["blocked_rows"][0]["region"] == "south"

        # 审计接口
        audit = client.get(f"/api/forensic/requests/{rid}/audit").json()
        actions = [item["动作"] for item in audit["items"]]
        # 撤权发生在数据包准备之后，统一归入准备期间撤回
        assert "准备期间撤回" in actions
        assert "撤回共享" not in actions

    def test_forged_credential_returns_403(self, client):
        _seed_two_region_data()
        created = client.post("/api/forensic/requests", json={
            "subject": "伪凭证", "regions": ["north"],
        }).json()
        rid = created["entry"]["id"]
        client.post(f"/api/forensic/requests/{rid}/authorize",
                    json={"region": "north", "authority_ref": "a"})
        client.post(f"/api/forensic/requests/{rid}/issue")
        client.post(f"/api/forensic/requests/{rid}/prepare")

        resp = client.post(f"/api/forensic/requests/{rid}/download",
                           json={"credential": "cred-forged"})
        assert resp.status_code == 403
        assert "拦截" in resp.json()["message"]

    def test_credential_scope_overflow_returns_403(self, client):
        _seed_two_region_data()
        created = client.post("/api/forensic/requests", json={
            "subject": "越权提交", "regions": ["north"],
        }).json()
        rid = created["entry"]["id"]
        client.post(f"/api/forensic/requests/{rid}/authorize",
                    json={"region": "north", "authority_ref": "a"})
        credential = client.post(f"/api/forensic/requests/{rid}/issue").json()["credential"]
        client.post(f"/api/forensic/requests/{rid}/prepare")

        resp = client.post(f"/api/forensic/requests/{rid}/download",
                           json={"credential": credential, "regions": ["north", "south"]})
        assert resp.status_code == 403
        assert "凭证不能扩大权限" in resp.json()["message"]

    def test_audit_module_listable_via_resource_router(self, client):
        resp = client.get("/api/forensic_audit")
        assert resp.status_code == 200
        assert resp.json()["items"] == [] or isinstance(resp.json()["items"], list)

    def test_lineage_written_and_readable(self, client):
        _seed_two_region_data()
        created = client.post("/api/forensic/requests", json={
            "subject": "血缘核对", "regions": ["north", "south"],
        }).json()
        rid = created["entry"]["id"]
        client.post(f"/api/forensic/requests/{rid}/authorize",
                    json={"region": "north", "authority_ref": "a-n"})
        client.post(f"/api/forensic/requests/{rid}/authorize",
                    json={"region": "south", "authority_ref": "a-s"})
        credential = client.post(f"/api/forensic/requests/{rid}/issue").json()["credential"]
        client.post(f"/api/forensic/requests/{rid}/prepare")
        client.post(f"/api/forensic/requests/{rid}/download",
                    json={"credential": credential})

        lineage_resp = client.get("/api/data_lineage")
        forensic_lineage = [
            row for row in lineage_resp.json()["items"]
            if row.get("取证编号") == created["entry"]["取证编号"]
        ]
        assert len(forensic_lineage) == 1
        assert "放行3行" in forensic_lineage[0]["访问结论"]
        # store 内实际读取范围包含两个区域
        stored = [r for r in store.rows("data_lineage")
                  if r.get("取证编号") == created["entry"]["取证编号"]][0]
        assert "north" in stored["实际读取范围"] and "south" in stored["实际读取范围"]
