import { request } from './client'

export type RegionGrant = {
  region: string
  status: '待核准' | '已授权' | '已撤回'
  granted_at: string
  revoked_at: string
  grant_version: number
  authority_ref: string
  remark: string
}

export type ForensicEntry = {
  id: number
  取证编号: string
  申请主题: string
  涉及区域: string
  已授权区域: string
  撤回区域: string
  数据包状态: string
  签发凭证: string
  访问结论: string
  更新时间: string
  status: string
  abnormal: boolean
  credential_scope?: string[]
  区域别名映射?: string
}

export type ForensicRow = {
  record_id: number
  batch_no: string
  line_no: string
  region: string
  raw_body: string
  field_attribution: Record<string, string>
  grant_version: number
  authority_ref: string
  verified_at: string
  content_digest: string
}

export type BlockedRow = {
  record_id: number
  region: string
  reason: string
}

export type ReopenSnapshot = {
  ok: boolean
  entry: ForensicEntry
  grants: RegionGrant[]
  readable_regions: string[]
  pending_regions: string[]
  revoked_regions: string[]
  readable_record_count: number
  package_ready: boolean
  package_summary: {
    package_no: string
    included: number
    blocked: number
    manifest: Record<string, unknown>
  } | null
  audit: AuditItem[]
}

export type AuditItem = {
  id: number
  取证编号: string
  动作: string
  区域: string
  操作人: string
  时间: string
  结论: string
  详情: string
  status: string
  abnormal: boolean
}

export type DownloadResult = {
  ok: boolean
  blocked: boolean
  message: string
  package_no?: string
  manifest?: Record<string, unknown>
  delivered?: ForensicRow[]
  blocked_rows?: BlockedRow[]
  conclusion?: {
    downloaded_at: string
    delivered_count: number
    blocked_count: number
    delivered_regions: string[]
    blocked: BlockedRow[]
  }
}

async function postJson<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const response = await request(path, { method: 'POST', body: JSON.stringify(body) })
  return (await response.json()) as T
}

export async function createForensicRequest(
  subject: string,
  regions: string[],
  scopeNote = '',
): Promise<{ ok: boolean; message: string; entry?: ForensicEntry }> {
  return postJson('/api/forensic/requests', { subject, regions, scope_note: scopeNote })
}

export async function authorizeRegion(
  requestId: number,
  region: string,
  authorityRef: string,
): Promise<{ ok: boolean; message: string }> {
  return postJson(`/api/forensic/requests/${requestId}/authorize`, {
    region,
    authority_ref: authorityRef,
  })
}

export async function revokeRegion(
  requestId: number,
  region: string,
  reason: string,
): Promise<{ ok: boolean; message: string }> {
  return postJson(`/api/forensic/requests/${requestId}/revoke`, { region, reason })
}

export async function issueCredential(
  requestId: number,
): Promise<{ ok: boolean; message: string; credential?: string }> {
  return postJson(`/api/forensic/requests/${requestId}/issue`, {})
}

export async function preparePackage(
  requestId: number,
): Promise<{ ok: boolean; message: string; package?: { rows: ForensicRow[]; blocked: BlockedRow[] } }> {
  return postJson(`/api/forensic/requests/${requestId}/prepare`, {})
}

export async function reopenRequest(requestId: number): Promise<ReopenSnapshot> {
  const response = await request(`/api/forensic/requests/${requestId}/reopen`)
  return (await response.json()) as ReopenSnapshot
}

export async function downloadPackage(
  requestId: number,
  credential: string,
  regions: string[] | null = null,
): Promise<DownloadResult> {
  const response = await request(`/api/forensic/requests/${requestId}/download`, {
    method: 'POST',
    body: JSON.stringify({ credential, regions }),
  })
  return (await response.json()) as DownloadResult
}
