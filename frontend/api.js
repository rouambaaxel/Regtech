/**
 * ComplianceOS — Frontend API Client
 * Remplace les données statiques du dashboard par de vrais appels API.
 * Coller dans ton projet React/Next.js.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ─── Auth headers (stocker en localStorage ou via un auth provider) ───
function authHeaders() {
  return {
    "Content-Type": "application/json",
    "X-Tenant-Id": localStorage.getItem("tenantId") || "",
    "X-Api-Key":   localStorage.getItem("apiKey")   || "",
  };
}

// ─── Generic fetch wrapper with error handling ───
async function apiFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { ...authHeaders(), ...(options.headers || {}) },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "API error");
  }
  return res.json();
}

// ═══════════════════════════════════════════════
// DASHBOARD STATS
// ═══════════════════════════════════════════════
export async function getStats() {
  return apiFetch("/api/v1/stats");
}

// ═══════════════════════════════════════════════
// KYB — BUSINESSES
// ═══════════════════════════════════════════════
export async function listBusinesses({ status, riskLevel, search, page = 1, perPage = 25 } = {}) {
  const params = new URLSearchParams({ page, per_page: perPage });
  if (status)    params.set("status", status);
  if (riskLevel) params.set("risk_level", riskLevel);
  if (search)    params.set("search", search);
  return apiFetch(`/api/v1/businesses?${params}`);
}

export async function getBusiness(id) {
  return apiFetch(`/api/v1/businesses/${id}`);
}

export async function runKYB(companyNumber, notes = "") {
  // Step 1: Queue the job
  const job = await apiFetch("/api/v1/kyb", {
    method: "POST",
    body: JSON.stringify({ company_number: companyNumber, notes }),
  });

  // Step 2: Poll until complete (max 30s)
  const maxAttempts = 15;
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, 2000));
    const status = await apiFetch(`/api/v1/kyb/jobs/${job.job_id}`);
    if (status.kyb_status) return status; // Pipeline completed
  }
  throw new Error("KYB timed out — check dashboard for results");
}

export async function rescreenBusiness(businessId) {
  return apiFetch(`/api/v1/businesses/${businessId}/rescreen`, { method: "POST" });
}

// ═══════════════════════════════════════════════
// AML ALERTS
// ═══════════════════════════════════════════════
export async function listAlerts({ status, severity, page = 1 } = {}) {
  const params = new URLSearchParams({ page, per_page: 25 });
  if (status)   params.set("status", status);
  if (severity) params.set("severity", severity);
  return apiFetch(`/api/v1/alerts?${params}`);
}

export async function getAlert(id) {
  return apiFetch(`/api/v1/alerts/${id}`);
}

export async function updateAlert(id, { status, notes }) {
  return apiFetch(`/api/v1/alerts/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ status, notes }),
  });
}

export async function fileSAR(alertId, { narrative, personsInvolved }) {
  return apiFetch(`/api/v1/alerts/${alertId}/sar`, {
    method: "POST",
    body: JSON.stringify({
      alert_id: alertId,
      suspicion_narrative: narrative,
      persons_involved: personsInvolved,
    }),
  });
}

// ═══════════════════════════════════════════════
// CASS 15 — SAFEGUARDING
// ═══════════════════════════════════════════════
export async function listReconciliations(days = 30) {
  return apiFetch(`/api/v1/cass15/reconciliations?days=${days}`);
}

export async function submitReconciliation({ date, totalFunds, safeguardedAmount, accounts = [], notes = "" }) {
  return apiFetch("/api/v1/cass15/reconciliations", {
    method: "POST",
    body: JSON.stringify({
      record_date: date,
      total_relevant_funds: totalFunds,
      safeguarded_amount: safeguardedAmount,
      accounts,
      discrepancy_notes: notes,
    }),
  });
}

export async function getSup16Return(year, month) {
  return apiFetch(`/api/v1/cass15/sup16-return?year=${year}&month=${month}`);
}

// ═══════════════════════════════════════════════
// FCA REPORTS
// ═══════════════════════════════════════════════
export async function listReports() {
  return apiFetch("/api/v1/reports");
}

export async function createReport({ reportType, periodStart, periodEnd, payload = {}, mlroSignOff = false }) {
  return apiFetch("/api/v1/reports", {
    method: "POST",
    body: JSON.stringify({
      report_type: reportType,
      period_start: periodStart,
      period_end: periodEnd,
      payload,
      mlro_sign_off: mlroSignOff,
    }),
  });
}

export async function submitReport(reportId) {
  return apiFetch(`/api/v1/reports/${reportId}/submit`, { method: "POST" });
}

// ═══════════════════════════════════════════════
// AUDIT LOG
// ═══════════════════════════════════════════════
export async function listAudit({ action, entityType, page = 1 } = {}) {
  const params = new URLSearchParams({ page, per_page: 50 });
  if (action)     params.set("action", action);
  if (entityType) params.set("entity_type", entityType);
  return apiFetch(`/api/v1/audit?${params}`);
}

// ═══════════════════════════════════════════════
// REACT HOOKS (Next.js / React 18+)
// ═══════════════════════════════════════════════
/**
 * Usage in your dashboard component:
 *
 * import { useEffect, useState } from "react";
 * import { getStats, listBusinesses, listAlerts } from "@/lib/api";
 *
 * export default function Dashboard() {
 *   const [stats, setStats]     = useState(null);
 *   const [businesses, setBiz]  = useState([]);
 *   const [alerts, setAlerts]   = useState([]);
 *
 *   useEffect(() => {
 *     Promise.all([getStats(), listBusinesses(), listAlerts({ status: "open" })])
 *       .then(([s, b, a]) => {
 *         setStats(s);
 *         setBiz(b.data);
 *         setAlerts(a.data);
 *       });
 *   }, []);
 *
 *   // ... render with real data
 * }
 */
