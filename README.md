# 多源日志采集与解析中心

管理多来源日志接入、字段解析、批量去重和水位推进的数据采集平台

这是一个前后端分离的管理平台：前端 Vue 3 + Vite + TypeScript，后端 FastAPI（Python）。
两边各自独立启动，前端 dev server 已关掉自动打开页面，启动后按终端打印的地址手工打开。

## 目录结构

```text
.
├── frontend/                 Vue 3 + Vite + TypeScript 前端
│   ├── src/views/WorkbenchView.vue|tsx  全部模块共享工作台
│   ├── src/data/modules.ts              18个业务模块配置
│   ├── src/api/              统一请求封装
│   └── vite.config.ts        dev server 配置（open: false）
├── backend/                  FastAPI（Python） 后端
│   ├── app/routers/resource.py  通用查询/导出/登记/动作接口
│   ├── app/services/<key>.py    每个模块独立领域逻辑
│   ├── app/services/base.py     共享服务骨架
│   └── app/store.py          内存数据仓库与示例数据
├── .gitignore
└── docker-compose.yml
```

## 启动

### 后端

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./run.sh
```

健康检查：`curl http://127.0.0.1:8013/api/health`

### 前端

```bash
cd frontend
npm ci
npm run dev
```

前端默认监听 `http://127.0.0.1:5193/`，dev server 不会自动打开浏览器，
需要自己访问。`/api` 由 vite 代理到后端 `http://127.0.0.1:8013`。

## 业务模块

| 模块 | 目录 | 业务对象 | 主要字段 |
| --- | --- | --- | --- |
| 数据源登记 | `source_registry` | 数据源 | 来源标识、接入协议、连接凭证 |
| 采集批次 | `ingest_batch` | 采集批次 | 批次编号、所属数据源、采集时间窗口 |
| 字段解析规则 | `field_parser` | 解析规则 | 规则名称、适用数据源、输入格式 |
| 原始日志记录 | `raw_records` | 日志记录 | 批次编号、原始行号、采集时间戳 |
| 标准化明细 | `parsed_entity` | 标准化记录 | 来源批次、原始记录ID、解析规则版本 |
| 去重引擎 | `dedup_engine` | 去重策略 | 策略名称、去重键字段、去重窗口 |
| 水位管理器 | `watermark_mgr` | 采集水位 | 数据源、最后成功批次、当前水位值 |
| 重试队列 | `retry_queue` | 重试任务 | 失败记录ID、失败原因、重试次数 |
| 格式适配层 | `format_adapter` | 格式适配 | 输入格式名、适配器类型、目标格式 |
| 质量校验规则 | `quality_check` | 校验规则 | 规则名称、校验类型、阈值参数 |
| 归档策略 | `data_archive` | 归档策略 | 策略名称、归档周期、保留时长 |
| 限流控制器 | `rate_limiter` | 限流规则 | 数据源、每秒上限、突发并发 |
| 解析操作日志 | `parse_journal` | 解析日志 | 操作类型、批次编号、执行时间 |
| RPA采集流程 | `rpa_workflow` | 采集流程 | 流程名称、目标系统、触发方式 |
| Schema版本 | `schema_version` | Schema版本 | 版本号、适用数据源、字段定义 |
| 采集告警策略 | `alert_policy` | 告警策略 | 策略名称、监控指标、告警阈值 |
| 数据导出 | `data_export` | 导出任务 | 导出范围、目标格式、过滤条件 |
| 回溯重放引擎 | `replay_engine` | 重放任务 | 历史批次范围、新解析规则版本、重放状态 |
| 聚合查询视图 | `aggregation_view` | 聚合视图 | 视图名称、聚合维度、指标定义 |
| 采集血缘 | `data_lineage` | 血缘关系 | 来源批次、解析规则版本、标准化版本 |
| 跨区域取证交付 | `forensic_delivery` | 取证申请 | 取证编号、涉及区域、区域授权、签发凭证、访问结论 |
| 取证审计条目 | `forensic_audit` | 取证审计 | 取证编号、动作、区域、结论 |

## 跨区域日志明细取证

`forensic_delivery` 承载跨区域取证的完整生命周期，专用接口挂在 `/api/forensic/*`，
通用查询/导出仍走 `/api/forensic_delivery` 资源路由：

1. **发起申请**：`POST /api/forensic/requests`，区域编码经别名表归一
   （如 `cn-north-1`、`华南`），兼容历史取证的区域归属引用。
2. **区域授权 / 撤回**：每个区域独立维护「待核准 / 已授权 / 已撤回」三态，
   支持两个区域先后授权；撤回后不可重新授权，剩余授权区域仍可继续取证。
3. **签发凭证**：凭证绑定申请与当时授权区域，跨区域提交凭证不能扩大权限。
4. **准备授权取证数据包**：逐行核验当时权限并按来源区域裁剪原始行，
   共享与撤权并发（含准备期间撤回）时只交付能核验当时权限的区域明细，
   被排除行记录拦截原因（尚未核准 / 已撤回 / 归属不符 / 归属不明）。
5. **重新打开入口**：`GET /api/forensic/requests/{id}/reopen` 返回剩余可读区域、
   待核准与已撤回区域、可读原始行数、数据包摘要与审计链路。
6. **下载交付**：`POST /api/forensic/requests/{id}/download` 再次逐行复核实时权限，
   归属不符内容拦截，伪凭证 / 越权区域返回 403，访问结论回写取证清单与采集血缘。
7. **血缘联动**：数据包的实际读取范围（区域、授权版本、授权依据、记录ID、行数）
   登记到 `data_lineage`，下载结论同步回写，可逐字段核对区域归属。

对应测试：`backend/tests/test_forensic_delivery.py`（服务层 22 例）与
`backend/tests/test_forensic_api.py`（HTTP 端到端 5 例）。

## 约定

- 全部模块共享`frontend/src/views/WorkbenchView.vue|tsx`和一套资源路由。
- 每个模块仍保留独立`backend/app/services/<模块>.py`；纯前端保留
  `frontend/src/domain/<模块>.ts`，用于承载真实业务差异并维持36题位容量。
- 列表接口统一返回 `{ items, total, page, size }`，动作接口统一返回 `{ ok, message }`。
- 状态流转只允许在 `app/services` 里改，路由层不做业务判断。

领域：数据工程
子方向：数据采集、爬虫与RPA
