const $ = (id) => document.getElementById(id);

async function api(url, options={}) {
  const response = await fetch(url, {headers: {"Content-Type":"application/json"}, ...options});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
async function loadDashboard() {
  const data = await api("/api/dashboard");
  const labels = [
    ["people_monitored","Pseudonymous identities"],
    ["linked_accounts","Linked platform accounts"],
    ["active_permissions","Active permissions"],
    ["investigations","Investigation reports"]
  ];
  $("stats").innerHTML = labels.map(([key,label]) => `<div class="stat"><strong>${data.stats[key] ?? 0}</strong><span>${label}</span></div>`).join("");
  const platforms = data.platforms || [];
  $("platforms").innerHTML = platforms.length ? platforms.map(p => {
    const live = p.source_type === "live_api";
    const readOnly = p.platform_name === "Department Drive";
    return `<article class="platform-card">
      <div class="platform-top"><div class="platform-name"><h3>${escapeHtml(p.platform_name)}</h3>${readOnly ? '<span class="readonly-pill">READ ONLY</span>' : ''}</div><span class="source-pill ${live ? "live" : "simulated"}">${live ? "LIVE API" : "SIMULATED"}</span></div>
      <p><strong>${p.linked_accounts}</strong> linked accounts · <strong>${p.active_permissions}</strong> active permissions</p>
      <p class="muted small">Last sync: ${escapeHtml(p.last_synced_at || "Not synced")}</p>
    </article>`;
  }).join("") : '<p class="muted">No platform data has been synchronised yet.</p>';
}
async function loadAudit() {
  const rows = await api("/api/audit");
  $("auditRows").innerHTML = rows.length ? rows.map(r => `<tr><td>${escapeHtml(r.created_at)}</td><td><code>${escapeHtml(r.person_token)}</code></td><td>${escapeHtml(r.actor)}</td><td>${escapeHtml(r.action)}</td><td>${escapeHtml(r.details)}</td></tr>`).join("") : '<tr><td colspan="5">No audit entries yet.</td></tr>';
}
async function syncPlatforms() {
  const button = $("syncPlatformsBtn");
  button.disabled = true;
  button.textContent = "Synchronising…";
  $("connectorStatus").textContent = "Retrieving pseudonymous records from the configured read-only connectors…";
  try {
    const data = await api("/api/platforms/sync", {method:"POST", body:"{}"});
    const successful = data.results.filter(x => x.status === "success");
    const failed = data.results.filter(x => x.status === "error");
    const warningCount = successful.reduce((n, x) => n + (x.warnings || []).length, 0);
    $("connectorStatus").textContent = `${successful.length} connector(s) synchronised, ${failed.length} failed, ${warningCount} record warning(s).`;
    await loadDashboard();
    if (failed.length) $("connectorStatus").textContent += " Check the connector configuration and terminal for details.";
  } catch(e) {
    $("connectorStatus").textContent = e.message;
  } finally {
    button.disabled = false;
    button.textContent = "Sync platform data";
  }
}
async function investigateEveryone() {
  const button = $("investigateAllBtn");
  const panel = $("result");
  button.disabled = true;
  button.textContent = "Investigating everyone…";
  panel.className = "result";
  panel.textContent = "CampusGhost is investigating pseudonymous records…";
  let progressTimer = null;
  try {
    progressTimer = setInterval(async () => {
      try {
        const progress = await api("/api/investigation-progress");
        if (progress.active) {
          panel.textContent = `Investigating ${progress.current || "next case"} — ${progress.completed}/${progress.total} completed. ${progress.message || ""}`;
        }
      } catch (_) { /* The main investigation request reports the actionable error. */ }
    }, 1000);
    const data = await api("/api/investigate-all", {method:"POST", body:"{}"});
    const results = data.results;
    panel.innerHTML = `<p class="eyebrow">DATABASE-WIDE INVESTIGATION</p><h3>Risk-ranked findings</h3><p class="muted small">Reviewed ${data.total_records} pseudonymous records. Unnecessary access is listed first, cases requiring human review next, followed by access supported by available evidence.</p>` +
      (results.length ? results.map(r => {
        const actionText = r.recommendation === "RECOMMEND_REVOKE"
          ? "Recommended next step: an authorised administrator can compare the identity and permission details in the admin portal, then revoke eligible access."
          : r.recommendation === "ESCALATE"
            ? "Recommended next step: an administrator should inspect the case because the available evidence is incomplete or unclear."
            : "The available evidence supports retaining the access, subject to the institution's normal review policy.";
        return `<article class="finding"><div class="person-top"><div><p class="eyebrow">RANK #${r.rank}</p><h3><code>${escapeHtml(r.person_token)}</code></h3></div><span class="recommendation ${r.recommendation}">${escapeHtml(r.recommendation.replaceAll("_"," "))}</span></div><p>${escapeHtml(r.reason)}</p><p class="muted small">Unnecessary accesses flagged: <b>${r.flagged_access_count}</b> · Excessive for role: <b>${r.excessive_access_count||0}</b> · Expired accesses: <b>${r.expired_access_count}</b> · Active accesses: <b>${r.active_permission_count}</b> · Report #${r.investigation_id}</p><details><summary>Evidence reviewed</summary><ul class="evidence">${r.evidence.map(x=>`<li>${escapeHtml(x)}</li>`).join("")}</ul><p class="muted small">Analysis mode: ${escapeHtml(r.ai_mode)}</p></details><p class="admin-next-step">${escapeHtml(actionText)}</p></article>`;
      }).join("") : '<p>No pseudonymous records were available for investigation.</p>');
    await loadDashboard();
    await loadAudit();
  } catch(e) {
    panel.textContent = e.message;
  } finally {
    if (progressTimer) clearInterval(progressTimer);
    button.disabled = false;
    button.textContent = "Investigate everyone";
  }
}
$("syncPlatformsBtn").addEventListener("click", syncPlatforms);
$("resetBtn").addEventListener("click", async()=>{
  if (!confirm("Reset the fictional pseudonymous records, platform accounts, investigations and audit logs?")) return;
  try {
    await api("/api/reset",{method:"POST",body:"{}"});
    $("result").className="result empty";
    $("result").textContent="Pseudonymous demo records reset. Run a database-wide investigation to review the simulated platform accounts.";
    $("connectorStatus").textContent="Demo records reset and simulated platform exports synchronised.";
    await loadDashboard();
    await loadAudit();
  } catch(e){alert(e.message);}
});
$("investigateAllBtn").addEventListener("click", investigateEveryone);
(async()=>{try{await loadDashboard();await loadAudit();}catch(e){$("platforms").textContent=e.message;}})();
