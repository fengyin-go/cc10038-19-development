<template>
  <section class="page" data-module="forensic_delivery">
    <header class="page-head">
      <div>
        <h2>跨区域取证交付</h2>
        <p class="page-desc">
          按区域授权裁剪原始日志行，准备授权取证数据包；撤权后重新打开入口，
          继续读取已授权区域明细，拦截归属不符的下载。
        </p>
      </div>
      <div class="page-actions">
        <button class="btn primary" data-testid="open-create" type="button" @click="openCreate">
          发起取证申请
        </button>
        <button class="btn" type="button" @click="reloadList">刷新清单</button>
      </div>
    </header>

    <div class="stat-row">
      <article class="stat-card">
        <span class="stat-label">取证申请数</span>
        <strong class="stat-value">{{ rows.length }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">可下载申请</span>
        <strong class="stat-value">{{ downloadableCount }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">部分撤回申请</span>
        <strong class="stat-value">{{ revokedCount }}</strong>
      </article>
    </div>

    <table class="data-table" data-testid="forensic-table">
      <thead>
        <tr>
          <th v-for="column in meta.fields" :key="column">{{ column }}</th>
          <th>当前状态</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="String(row.id)" :data-testid="`row-${row.id}`" :data-status="String(row.status)">
          <td v-for="column in meta.fields" :key="column">{{ row[column] || '—' }}</td>
          <td>
            <span :class="['status-badge', row.abnormal ? 'status-bad' : '']">{{ row.status }}</span>
          </td>
          <td class="row-actions">
            <button class="link" type="button" :data-testid="`open-${row.id}`" @click="openDetail(row.id)">
              打开取证入口
            </button>
          </td>
        </tr>
        <tr v-if="!rows.length">
          <td :colspan="meta.fields.length + 2" class="empty-state">暂无取证申请，先发起一单跨区域取证</td>
        </tr>
      </tbody>
    </table>

    <!-- 新建取证申请 -->
    <div v-if="showCreate" class="modal-backdrop" data-testid="create-modal">
      <form class="modal" @submit.prevent="submitCreate">
        <h3>发起跨区域取证申请</h3>
        <label class="create-field">
          <span>申请主题</span>
          <input v-model="createForm.subject" data-testid="create-subject" required />
        </label>
        <label class="create-field">
          <span>涉及区域（多个区域用逗号分隔，支持历史别名如 cn-north-1、华南）</span>
          <input v-model="createForm.regionsText" data-testid="create-regions" placeholder="north,south" required />
        </label>
        <label class="create-field">
          <span>取证范围说明</span>
          <input v-model="createForm.scopeNote" data-testid="create-scope" />
        </label>
        <p v-if="createError" class="error-text">{{ createError }}</p>
        <div class="page-actions">
          <button class="btn" type="button" @click="showCreate = false">取消</button>
          <button class="btn primary" data-testid="submit-create" type="submit">确认登记</button>
        </div>
      </form>
    </div>

    <!-- 取证详情工作台 -->
    <div v-if="snapshot" class="modal-backdrop forensic-backdrop" data-testid="detail-modal">
      <div class="modal forensic-modal">
        <div class="detail-head">
          <h3>取证入口 · {{ snapshot.entry.取证编号 }}</h3>
          <button class="btn ghost" type="button" @click="snapshot = null">关闭</button>
        </div>
        <p class="page-desc">{{ snapshot.entry.申请主题 }}　状态：{{ snapshot.entry.status }}</p>

        <div class="grant-grid">
          <div v-for="grant in snapshot.grants" :key="grant.region" class="grant-card" :data-status="grant.status">
            <div class="grant-region">{{ grant.region }}</div>
            <span :class="['grant-status', grantStatusClass(grant.status)]">{{ grant.status }}</span>
            <div class="grant-meta">
              <div v-if="grant.authority_ref">授权依据：{{ grant.authority_ref }}（v{{ grant.grant_version }}）</div>
              <div v-if="grant.granted_at">授权时间：{{ grant.granted_at }}</div>
              <div v-if="grant.revoked_at">撤回时间：{{ grant.revoked_at }}</div>
              <div v-if="grant.remark">说明：{{ grant.remark }}</div>
            </div>
            <div class="row-actions">
              <button
                v-if="grant.status === '待核准'"
                class="btn"
                type="button"
                :data-testid="`authorize-${grant.region}`"
                @click="onAuthorize(grant.region)"
              >
                核准授权
              </button>
              <button
                v-if="grant.status === '已授权'"
                class="btn"
                type="button"
                :data-testid="`revoke-${grant.region}`"
                @click="onRevoke(grant.region)"
              >
                撤回共享
              </button>
            </div>
          </div>
        </div>

        <div class="scope-summary">
          <span>可继续取证区域：<strong>{{ snapshot.readable_regions.join('、') || '无' }}</strong></span>
          <span>待核准：{{ snapshot.pending_regions.join('、') || '—' }}</span>
          <span>已撤回：{{ snapshot.revoked_regions.join('、') || '—' }}</span>
          <span>当前可读原始行：{{ snapshot.readable_record_count }}</span>
        </div>

        <div class="page-actions detail-actions">
          <button
            class="btn primary"
            type="button"
            data-testid="issue-credential"
            :disabled="!snapshot.readable_regions.length || !!snapshot.entry.签发凭证"
            @click="onIssue"
          >
            {{ snapshot.entry.签发凭证 ? '凭证已签发' : '签发取证凭证' }}
          </button>
          <button
            class="btn primary"
            type="button"
            data-testid="prepare-package"
            :disabled="!snapshot.entry.签发凭证 || snapshot.entry.数据包状态 === '准备中'"
            @click="onPrepare"
          >
            准备授权取证数据包
          </button>
          <button
            class="btn"
            type="button"
            data-testid="download-package"
            :disabled="!snapshot.package_ready"
            @click="onDownload(null)"
          >
            按凭证范围下载
          </button>
          <button
            class="btn"
            type="button"
            data-testid="download-north-only"
            :disabled="!snapshot.package_ready || !snapshot.readable_regions.length"
            @click="onDownload(snapshot.readable_regions)"
          >
            仅下载当前授权区域
          </button>
        </div>

        <div v-if="snapshot.entry.签发凭证" class="credential-line">
          签发凭证：<code>{{ snapshot.entry.签发凭证 }}</code>
          （绑定范围：{{ (snapshot.entry.credential_scope || []).join('、') }}）
        </div>

        <div v-if="snapshot.package_summary" class="package-summary">
          <h4>授权取证数据包 {{ snapshot.package_summary.package_no }}</h4>
          <span>纳入明细：{{ snapshot.package_summary.included }} 行</span>
          <span>拦截明细：{{ snapshot.package_summary.blocked }} 行</span>
          <span>清单访问结论：{{ snapshot.entry.访问结论 }}</span>
        </div>

        <div v-if="downloadResult" class="download-result" :data-testid="downloadResultTestid">
          <h4>下载结论：{{ downloadResult.message }}</h4>
          <table v-if="downloadResult.delivered?.length" class="data-table inner-table">
            <thead>
              <tr><th>记录ID</th><th>区域归属</th><th>批次</th><th>行号</th><th>原始正文（已授权裁剪）</th></tr>
            </thead>
            <tbody>
              <tr v-for="row in downloadResult.delivered" :key="String(row.record_id)">
                <td>{{ row.record_id }}</td>
                <td>{{ row.region }}</td>
                <td>{{ row.batch_no }}</td>
                <td>{{ row.line_no }}</td>
                <td>{{ row.raw_body }}</td>
              </tr>
            </tbody>
          </table>
          <table v-if="downloadResult.blocked_rows?.length" class="data-table inner-table blocked-table">
            <thead>
              <tr><th>拦截记录ID</th><th>区域</th><th>拦截原因</th></tr>
            </thead>
            <tbody>
              <tr v-for="row in downloadResult.blocked_rows" :key="String(row.record_id)">
                <td>{{ row.record_id }}</td>
                <td>{{ row.region }}</td>
                <td>{{ row.reason }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <h4>审计条目（授权 / 撤回 / 准备 / 下载全链路）</h4>
        <table class="data-table inner-table" data-testid="audit-table">
          <thead>
            <tr><th>时间</th><th>动作</th><th>区域</th><th>操作人</th><th>结论</th></tr>
          </thead>
          <tbody>
            <tr v-for="item in snapshot.audit" :key="String(item.id)" :data-conclusion="item.结论">
              <td>{{ item.时间 }}</td>
              <td>{{ item.动作 }}</td>
              <td>{{ item.区域 || '—' }}</td>
              <td>{{ item.操作人 }}</td>
              <td :class="item.结论 === '拦截' ? 'error-text' : ''">{{ item.结论 }}</td>
            </tr>
          </tbody>
        </table>

        <p v-if="detailError" class="error-text">{{ detailError }}</p>
      </div>
    </div>

    <footer class="page-foot">
      <span>共 {{ rows.length }} 条取证申请</span>
      <span v-if="listError" class="error-text">{{ listError }}</span>
    </footer>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import { listEntries } from '@/api/backend-service'
import {
  authorizeRegion,
  createForensicRequest,
  downloadPackage,
  issueCredential,
  preparePackage,
  reopenRequest,
  revokeRegion,
  type DownloadResult,
  type ReopenSnapshot,
} from '@/api/forensic-service'
import { moduleMeta } from '@/data/modules'
import type { EntryRow } from '@/data/types'

const meta = moduleMeta('forensic_delivery')

const rows = ref<EntryRow[]>([])
const listError = ref('')
const showCreate = ref(false)
const createForm = ref({ subject: '', regionsText: '', scopeNote: '' })
const createError = ref('')
const snapshot = ref<ReopenSnapshot | null>(null)
const detailError = ref('')
const downloadResult = ref<DownloadResult | null>(null)

const downloadableCount = computed(
  () => rows.value.filter((row) => row.数据包状态 === '已就绪').length,
)
const revokedCount = computed(
  () => rows.value.filter((row) => String(row.撤回区域 || '') !== '').length,
)
const downloadResultTestid = computed(() =>
  downloadResult.value?.ok ? 'download-ok' : 'download-blocked',
)

function grantStatusClass(status: string): string {
  if (status === '已授权') return 'grant-ok'
  if (status === '已撤回') return 'grant-revoked'
  return 'grant-pending'
}

async function reloadList() {
  listError.value = ''
  try {
    const payload = await listEntries('forensic_delivery', { size: '100' })
    rows.value = payload.items as EntryRow[]
  } catch (error) {
    listError.value = error instanceof Error ? error.message : '取证清单读取失败'
  }
}

function openCreate() {
  createForm.value = { subject: '', regionsText: '', scopeNote: '' }
  createError.value = ''
  showCreate.value = true
}

async function submitCreate() {
  createError.value = ''
  const regions = createForm.value.regionsText
    .split(/[,，]/)
    .map((item) => item.trim())
    .filter(Boolean)
  const result = await createForensicRequest(
    createForm.value.subject,
    regions,
    createForm.value.scopeNote,
  )
  if (!result.ok) {
    createError.value = result.message
    return
  }
  showCreate.value = false
  await reloadList()
  if (result.entry) await openDetail(result.entry.id)
}

async function openDetail(id: number) {
  detailError.value = ''
  downloadResult.value = null
  try {
    snapshot.value = await reopenRequest(id)
  } catch (error) {
    detailError.value = error instanceof Error ? error.message : '取证入口打开失败'
  }
}

async function refreshSnapshot() {
  if (!snapshot.value) return
  snapshot.value = await reopenRequest(snapshot.value.entry.id)
  await reloadList()
}

async function onAuthorize(region: string) {
  if (!snapshot.value) return
  detailError.value = ''
  const authorityRef = `auth-${region}-${Date.now()}`
  const result = await authorizeRegion(snapshot.value.entry.id, region, authorityRef)
  if (!result.ok) detailError.value = result.message
  await refreshSnapshot()
}

async function onRevoke(region: string) {
  if (!snapshot.value) return
  detailError.value = ''
  const result = await revokeRegion(
    snapshot.value.entry.id,
    region,
    `值班台撤回 ${region} 区域共享`,
  )
  if (!result.ok) detailError.value = result.message
  await refreshSnapshot()
}

async function onIssue() {
  if (!snapshot.value) return
  detailError.value = ''
  const result = await issueCredential(snapshot.value.entry.id)
  if (!result.ok) detailError.value = result.message
  await refreshSnapshot()
}

async function onPrepare() {
  if (!snapshot.value) return
  detailError.value = ''
  const result = await preparePackage(snapshot.value.entry.id)
  if (!result.ok) detailError.value = result.message
  await refreshSnapshot()
}

async function onDownload(regions: string[] | null) {
  if (!snapshot.value) return
  detailError.value = ''
  try {
    downloadResult.value = await downloadPackage(
      snapshot.value.entry.id,
      snapshot.value.entry.签发凭证,
      regions,
    )
    if (!downloadResult.value.ok && downloadResult.value.blocked) {
      detailError.value = downloadResult.value.message
    }
  } catch (error) {
    detailError.value = error instanceof Error ? error.message : '下载请求失败'
  }
  await refreshSnapshot()
}

onMounted(reloadList)
</script>

<style scoped>
.status-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  background: #e8f0fe;
  color: #1f6feb;
  font-size: 12px;
}
.status-badge.status-bad {
  background: #fef3f2;
  color: #b42318;
}
.forensic-backdrop {
  place-items: start center;
}
.forensic-modal {
  width: min(960px, 96vw);
  max-height: 92vh;
  overflow: auto;
}
.detail-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.grant-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 10px;
  margin: 12px 0;
}
.grant-card {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 12px;
  background: #fafbfc;
}
.grant-region {
  font-weight: 600;
  margin-bottom: 6px;
}
.grant-status {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 12px;
  margin-bottom: 6px;
}
.grant-ok {
  background: #dcfae6;
  color: #15803d;
}
.grant-revoked {
  background: #fef3f2;
  color: #b42318;
}
.grant-pending {
  background: #f1f5f9;
  color: #64748b;
}
.grant-meta {
  font-size: 12px;
  color: var(--muted);
  display: flex;
  flex-direction: column;
  gap: 2px;
  margin-bottom: 8px;
}
.scope-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 14px;
  font-size: 13px;
  padding: 10px 12px;
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 12px;
}
.detail-actions {
  margin: 8px 0 12px;
  flex-wrap: wrap;
}
.credential-line {
  font-size: 13px;
  background: #f8fafc;
  border: 1px dashed var(--border);
  border-radius: 6px;
  padding: 8px 10px;
  margin-bottom: 12px;
}
.credential-line code {
  background: #eef2ff;
  padding: 1px 6px;
  border-radius: 4px;
}
.package-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  font-size: 13px;
  padding: 10px 12px;
  background: #f0fdf4;
  border: 1px solid #bbf7d0;
  border-radius: 8px;
  margin-bottom: 12px;
}
.download-result {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 12px;
  margin-bottom: 12px;
  background: #fff;
}
.inner-table {
  margin: 8px 0;
  font-size: 12px;
}
.blocked-table {
  background: #fff7f7;
}
button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
