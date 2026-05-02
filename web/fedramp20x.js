/**
 * FedRAMP 20x Evidence Explorer — loaded after app.js helpers; uses shared state.twentyx.
 */
(function () {
  "use strict";

  const API_BASE = "http://127.0.0.1:8081";

  function esc(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function badgeClass(result) {
    const r = String(result || "").toUpperCase();
    if (r === "PASS") return "pass";
    if (r === "PARTIAL") return "partial";
    if (r === "FAIL") return "fail";
    if (r === "OPEN") return "open";
    if (r === "NOT_APPLICABLE" || r === "N/A") return "missing";
    return "missing";
  }

  function simpleMdToHtml(md) {
    if (!md) return "<p class='warn'>No content.</p>";
    let h = esc(md);
    h = h.replace(/^### (.*)$/gm, "<h3>$1</h3>");
    h = h.replace(/^## (.*)$/gm, "<h2>$1</h2>");
    h = h.replace(/^# (.*)$/gm, "<h1>$1</h1>");
    h = h.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
    h = h.replace(/^- (.*)$/gm, "<li>$1</li>");
    h = h.replace(/(<li>.*<\/li>\n?)+/g, "<ul class='plain'>$&</ul>");
    h = h.replace(/\n\n+/g, "</p><p>");
    return "<div class='md-preview'><p>" + h + "</p></div>";
  }

  function parseKsiSections(md) {
    const out = {};
    if (!md) return out;
    const re = /^## `([^`]+)`\s/gm;
    const matches = [...md.matchAll(re)];
    matches.forEach((m, i) => {
      const start = m.index;
      const end = i + 1 < matches.length ? matches[i + 1].index : md.length;
      out[m[1]] = md.slice(start, end);
    });
    return out;
  }

  function extractJsonArray(doc, keys) {
    if (!doc) return [];
    if (Array.isArray(doc)) return doc.filter((x) => x && typeof x === "object");
    for (const k of keys) {
      const v = doc[k];
      if (Array.isArray(v)) return v.filter((x) => x && typeof x === "object");
    }
    return [];
  }

  function execMetricsFromPackage(pkg) {
    const catalog = (pkg && pkg.ksi_catalog) || [];
    const results = (pkg && pkg.ksi_validation_results) || [];
    const findings = (pkg && pkg.findings) || [];
    const poam = (pkg && pkg.poam_items) || [];
    const total = catalog.length || results.length;
    const autoTargetN = catalog.filter((k) => k && k.automation_target).length;
    const autoPct = total ? Math.round((10000 * autoTargetN) / total) / 100 : 0;
    const byId = {};
    results.forEach((r) => {
      if (r && r.ksi_id) byId[String(r.ksi_id)] = r;
    });
    const autoKsiIds = catalog.filter((k) => k && k.ksi_id && k.automation_target).map((k) => String(k.ksi_id));
    let autoPass = 0;
    const autoNotPass = [];
    autoKsiIds.forEach((kid) => {
      const row = byId[kid] || {};
      const st = String(row.status || "").toUpperCase();
      if (st === "PASS") autoPass += 1;
      else if (st) autoNotPass.push(kid + " (" + st + ")");
      else autoNotPass.push(kid + " (no validation row)");
    });
    let passed = 0,
      failed = 0,
      partial = 0,
      na = 0;
    results.forEach((r) => {
      const st = String((r && r.status) || "").toUpperCase();
      if (st === "PASS") passed++;
      else if (st === "FAIL") failed++;
      else if (st === "PARTIAL") partial++;
      else if (st === "OPEN") partial++;
      else if (st === "NOT_APPLICABLE" || st === "N/A") na++;
      else na++;
    });
    const openPoam = poam.filter((p) => {
      const s = String((p && p.status) || "").toLowerCase();
      return !s || s === "open" || s === "active";
    }).length;
    const openRisk = (f) => {
      const st = String((f && f.status) || "open").toLowerCase();
      if (st === "risk_accepted" || st === "closed" || st === "false_positive") return false;
      const ra = f.risk_acceptance;
      if (ra && typeof ra === "object" && ra.accepted_by) return false;
      return true;
    };
    const crit = findings.filter((f) => String(f.severity || "").toLowerCase() === "critical" && openRisk(f)).length;
    const high = findings.filter((f) => String(f.severity || "").toLowerCase() === "high" && openRisk(f)).length;
    return {
      total_ksis: total,
      passed,
      failed,
      partial,
      not_applicable: na,
      automation_target_ksis: autoTargetN,
      automation_catalog_percentage: autoPct,
      automation_target_passing: autoPass,
      automation_target_not_passing: autoNotPass,
      open_poam_items: openPoam,
      critical_open_findings: crit,
      high_open_findings: high,
    };
  }

  async function fetchText(url) {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(String(r.status));
    return r.text();
  }

  async function fetchJson(url) {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(String(r.status));
    return r.json();
  }

  async function tryUrls(paths) {
    const errs = [];
    for (const url of paths) {
      try {
        const r = await fetch(url, { cache: "no-store" });
        if (r.ok) return { url, r };
        errs.push(url + " → " + r.status);
      } catch (e) {
        errs.push(url + " → " + (e && e.message));
      }
    }
    return { error: errs.join("; ") };
  }

  function validationPaths(baseHref) {
    const u = new URL(baseHref);
    const root = u.href.replace(/\/?$/, "/");
    return [
      root + "evidence/validation-results/",
      new URL("../evidence/validation-results/", u).href,
    ];
  }

  async function loadSlice(baseHref, name) {
    const bases = validationPaths(baseHref);
    const tries = [];
    bases.forEach((b) => tries.push(b + name));
    const hit = await tryUrls(tries);
    if (hit.r) return hit.r.json();
    return null;
  }

  async function bootstrap(state) {
    const tx = {
      loaded: false,
      package: null,
      packageUrl: "",
      ksiResults: [],
      findings: [],
      poamItems: [],
      reconciliation: null,
      assessorKsiMd: "",
      executiveMd: "",
      execReadinessMd: "",
      aoMd: "",
      errors: [],
      ksiFilter: { theme: "", status: "", mode: "", autoMin: "", autoMax: "", control: "" },
      selectedKsiId: null,
      selectedFindingId: null,
      aiSubtab: "assessment",
    };
    state.twentyx = tx;

    const bases = [
      new URL("../evidence/package/", window.location.href).href,
      new URL("sample-data/20x-package/", window.location.href).href,
    ];
    const pkgHit = await tryUrls(bases.map((b) => b + "fedramp20x-package.json"));
    if (!pkgHit.r) {
      tx.errors.push("No fedramp20x-package.json at ../evidence/package/ or web/sample-data/20x-package/.");
      wireTwentyx(state);
      renderAll(state);
      return;
    }
    tx.packageUrl = pkgHit.url;
    tx.package = await pkgHit.r.json();
    tx.loaded = true;

    const baseDir = tx.packageUrl.replace(/fedramp20x-package\.json$/i, "");

    const mergeKsi = (doc) => extractJsonArray(doc, ["ksi_validation_results", "ksi_results", "results"]);
    const mergeFind = (doc) => extractJsonArray(doc, ["findings"]);
    const mergePoam = (doc) => {
      const arr = extractJsonArray(doc, ["poam_items", "items"]);
      if (arr.length) return arr;
      if (doc && Array.isArray(doc.poam_items)) return doc.poam_items;
      return [];
    };

    try {
      const ksiDoc = await loadSlice(baseDir, "ksi-results.json");
      tx.ksiResults = ksiDoc ? mergeKsi(ksiDoc) : mergeKsi(tx.package);
    } catch (_) {
      tx.ksiResults = mergeKsi(tx.package);
    }
    try {
      const fDoc = await loadSlice(baseDir, "findings.json");
      tx.findings = fDoc ? mergeFind(fDoc) : mergeFind(tx.package);
    } catch (_) {
      tx.findings = mergeFind(tx.package);
    }
    try {
      const pDoc = await loadSlice(baseDir, "poam-items.json");
      tx.poamItems = pDoc ? mergePoam(pDoc) : mergePoam(tx.package);
    } catch (_) {
      tx.poamItems = mergePoam(tx.package);
    }
    try {
      const recDoc = await loadSlice(baseDir, "reconciliation.json");
      tx.reconciliation =
        recDoc && recDoc.checks
          ? recDoc
          : recDoc && recDoc.reconciliation_id
            ? recDoc
            : null;
    } catch (_) {
      tx.reconciliation = null;
    }

    const manifest = ((tx.package.reconciliation_summary || {}).human_report_manifest) || [];
    const resolveReport = (role, defaultSeg) => {
      const m = manifest.find((x) => x && x.role === role);
      const rel = (m && m.path) || defaultSeg;
      return baseDir + rel.split("/").map(encodeURIComponent).join("/");
    };
    try {
      tx.assessorKsiMd = await fetchText(resolveReport("assessor", "reports/assessor/ksi-by-ksi-assessment.md"));
    } catch (e) {
      tx.errors.push("ksi-by-ksi-assessment.md: " + e.message);
    }
    try {
      tx.executiveMd = await fetchText(resolveReport("executive", "reports/executive/executive-summary.md"));
    } catch (e) {
      tx.errors.push("executive-summary.md: " + e.message);
    }
    try {
      const execBase = new URL("reports/executive/", baseDir).href;
      tx.execReadinessMd = await fetchText(execBase + "authorization-readiness.md");
    } catch (e) {
      tx.errors.push("authorization-readiness.md: " + e.message);
    }
    try {
      tx.aoMd = await fetchText(resolveReport("agency_ao", "reports/agency-ao/ao-risk-brief.md"));
    } catch (e) {
      tx.errors.push("ao-risk-brief.md: " + e.message);
    }

    tx.ksiSections = parseKsiSections(tx.assessorKsiMd);
    const ids = (tx.ksiResults || []).map((r) => r && r.ksi_id).filter(Boolean);
    tx.selectedKsiId = ids[0] || null;
    wireTwentyx(state);
    renderAll(state);
  }

  function catalogById(pkg) {
    const m = {};
    ((pkg && pkg.ksi_catalog) || []).forEach((k) => {
      if (k && k.ksi_id) m[String(k.ksi_id)] = k;
    });
    return m;
  }

  function resultById(tx) {
    const m = {};
    (tx.ksiResults || []).forEach((r) => {
      if (r && r.ksi_id) m[String(r.ksi_id)] = r;
    });
    return m;
  }

  function registryById(pkg) {
    const m = {};
    const srcs = ((pkg.evidence_source_registry || {}).sources) || [];
    srcs.forEach((s) => {
      if (s && s.id) m[String(s.id)] = s;
    });
    return m;
  }

  function findingsForKsi(tx, kid) {
    return (tx.findings || []).filter((f) => {
      const ks = f.linked_ksi_ids || f.ksi_ids || [];
      return Array.isArray(ks) && ks.indexOf(kid) >= 0;
    });
  }

  function poamForFinding(tx, fid) {
    return (tx.poamItems || []).filter((p) => p && (p.finding_id === fid || p.finding_id === String(fid)));
  }

  function renderDashboard(state) {
    const tx = state.twentyx;
    const el = document.getElementById("20x-dashboard-cards");
    const stEl = document.getElementById("20x-load-line");
    if (!el) return;
    if (!tx || !tx.loaded || !tx.package) {
      el.innerHTML = "<p class='warn'>Build the 20x package to <code>evidence/package/</code> (see serve_web hint).</p>";
      return;
    }
    const m = execMetricsFromPackage(tx.package);
    const rec = tx.reconciliation || {};
    const cards = [
      ["Total KSIs", m.total_ksis],
      ["Addressed KSIs (non N/A)", m.total_ksis - m.not_applicable],
      ["Automation % (catalog)", m.automation_catalog_percentage + "%"],
      ["PASS / FAIL / PARTIAL", m.passed + " / " + m.failed + " / " + m.partial],
      ["Open POA&M", m.open_poam_items],
      ["Open critical / high findings", m.critical_open_findings + " / " + m.high_open_findings],
      ["Deep reconciliation", rec.overall_status || "—"],
    ];
    el.innerHTML = cards
      .map(
        ([l, v]) =>
          `<div class="card"><div class="label">${esc(l)}</div><div class="value">${esc(String(v))}</div></div>`
      )
      .join("");
    const paths = document.getElementById("20x-artifact-paths");
    if (paths) {
      const base = (tx.packageUrl || "").replace(/fedramp20x-package\.json.*/i, "");
      paths.innerHTML =
        "<ul class='plain'>" +
        [
          base + "fedramp20x-package.json",
          base + "evidence/validation-results/ksi-results.json",
          base + "evidence/validation-results/findings.json",
          base + "evidence/validation-results/poam-items.json",
          base + "evidence/validation-results/reconciliation.json",
        ]
          .map((u) => `<li><a href="${esc(u)}">${esc(u)}</a></li>`)
          .join("") +
        "</ul>";
    }
    if (stEl) stEl.textContent = tx.errors.length ? "20x warnings: " + tx.errors.join(" | ") : "FedRAMP 20x package loaded.";
  }

  function renderKsiExplorer(state) {
    const tx = state.twentyx;
    const listEl = document.getElementById("20x-ksi-list");
    const detailEl = document.getElementById("20x-ksi-detail");
    if (!listEl || !tx || !tx.package) return;
    const cat = catalogById(tx.package);
    const res = resultById(tx);
    const reg = registryById(tx.package);
    const fth = tx.ksiFilter;

    const themes = [...new Set(Object.values(cat).map((k) => k.theme).filter(Boolean))].sort();
    const filtBar = document.getElementById("20x-ksi-filters");
    if (filtBar && !filtBar.dataset.wired) {
      filtBar.dataset.wired = "1";
      filtBar.innerHTML = [
        "<label>Theme <select id='f20-theme'><option value=''>All</option>" +
          themes.map((t) => `<option value="${esc(t)}">${esc(t)}</option>`).join("") +
          "</select></label>",
        "<label>Status <select id='f20-status'><option value=''>All</option>" +
          ["PASS", "FAIL", "PARTIAL", "OPEN", "NOT_APPLICABLE", "N/A"]
            .map((s) => `<option value="${s}">${s}</option>`)
            .join("") +
          "</select></label>",
        "<label>Validation mode <select id='f20-mode'><option value=''>All</option>" +
          ["automated", "manual", "hybrid"].map((s) => `<option value="${s}">${s}</option>`).join("") +
          "</select></label>",
        "<label>Control <input id='f20-ctrl' type='text' placeholder='e.g. AU-6' style='width:6rem'/></label>",
        "<label>Auto score min <input id='f20-amin' type='number' min='0' max='5' style='width:3rem'/></label>",
        "<label>max <input id='f20-amax' type='number' min='0' max='5' style='width:3rem'/></label>",
      ].join(" ");
      ["f20-theme", "f20-status", "f20-mode", "f20-ctrl", "f20-amin", "f20-amax"].forEach((id) => {
        const n = document.getElementById(id);
        if (n)
          n.addEventListener("change", () => {
            tx.ksiFilter.theme = document.getElementById("f20-theme").value;
            tx.ksiFilter.status = document.getElementById("f20-status").value;
            tx.ksiFilter.mode = document.getElementById("f20-mode").value;
            tx.ksiFilter.control = (document.getElementById("f20-ctrl").value || "").trim().toUpperCase();
            tx.ksiFilter.autoMin = document.getElementById("f20-amin").value;
            tx.ksiFilter.autoMax = document.getElementById("f20-amax").value;
            renderKsiExplorer(state);
          });
        if (n && n.tagName === "INPUT") n.addEventListener("input", () => n.dispatchEvent(new Event("change")));
      });
    }

    function avgAutoScore(k) {
      const ids = (k && k.evidence_sources) || [];
      if (!ids.length) return null;
      let n = 0,
        s = 0;
      ids.forEach((id) => {
        const row = reg[String(id)];
        if (row && typeof row.automation_score === "number") {
          s += row.automation_score;
          n++;
        }
      });
      return n ? Math.round((100 * s) / n) / 100 : null;
    }

    const kids = Object.keys(cat).sort();
    const rows = kids
      .map((kid) => {
        const k = cat[kid];
        const r = res[kid] || {};
        const st = String(r.status || "").toUpperCase();
        if (fth.theme && k.theme !== fth.theme) return null;
        if (fth.status && st !== fth.status) return null;
        if (fth.mode && k.validation_mode !== fth.mode) return null;
        if (fth.control) {
          const lc = k.legacy_controls || {};
          const r4 = (lc.rev4 || []).join(" ");
          const r5 = (lc.rev5 || []).join(" ");
          if (!r4.includes(fth.control) && !r5.includes(fth.control)) return null;
        }
        const as = avgAutoScore(k);
        if (fth.autoMin !== "" && (as == null || as < Number(fth.autoMin))) return null;
        if (fth.autoMax !== "" && (as == null || as > Number(fth.autoMax))) return null;
        return { kid, k, r, st, as };
      })
      .filter(Boolean);

    listEl.innerHTML = rows
      .map(({ kid, st }) => {
        const sel = tx.selectedKsiId === kid ? " selected" : "";
        return `<tr class="ksi-row${sel}" data-kid="${esc(kid)}"><td><span class="badge ${badgeClass(st)}">${esc(
          st
        )}</span></td><td>${esc(kid)}</td></tr>`;
      })
      .join("");

    listEl.querySelectorAll(".ksi-row").forEach((tr) => {
      tr.addEventListener("click", () => {
        tx.selectedKsiId = tr.getAttribute("data-kid");
        renderKsiExplorer(state);
      });
    });

    const kid = tx.selectedKsiId;
    const k = kid ? cat[kid] : null;
    const r = kid ? res[kid] : null;
    if (!k) {
      detailEl.innerHTML = "<p class='warn'>Select a KSI.</p>";
      return;
    }
    const avgAuto = avgAutoScore(k);
    const lc = k.legacy_controls || {};
    const evIds = (k.evidence_sources || []).map((id) => reg[String(id)]).filter(Boolean);
    const crit = (k.pass_fail_criteria || []).filter((c) => c && typeof c === "object");
    const finds = findingsForKsi(tx, kid);
    const poams = [];
    finds.forEach((f) => poamForFinding(tx, f.finding_id).forEach((p) => poams.push(p)));
    const assessorSec = (tx.ksiSections && tx.ksiSections[kid]) || "";
    const rs = k.reporting_sections || {};
    detailEl.innerHTML = `
      <h3 style="margin-top:0">${esc(k.title || kid)}</h3>
      <p><span class="badge ${badgeClass(r && r.status)}">${esc((r && r.status) || "")}</span>
      <span style="color:var(--muted)"> theme: ${esc(k.theme || "")}</span></p>
      <p><strong>Objective:</strong> ${esc(k.objective || "")}</p>
      <p><strong>Validation mode:</strong> ${esc(k.validation_mode || "")}</p>
      <p><strong>Automation (avg registry score on linked sources):</strong> ${esc(avgAuto == null ? "—" : String(avgAuto))}</p>
      <p><strong>Rev4:</strong> ${esc((lc.rev4 || []).join(", "))} <strong>Rev5:</strong> ${esc((lc.rev5 || []).join(", "))}</p>
      <h4>Evidence sources (registry)</h4>
      <ul class="plain">${evIds
        .map(
          (s) =>
            `<li><code>${esc(s.id)}</code> — ${esc(s.name || "")} (score ${esc(String(s.automation_score))})</li>`
        )
        .join("")}</ul>
      <h4>Criteria</h4>
      <ul class="plain">${crit
        .map(
          (c) =>
            `<li><code>${esc(c.criteria_id)}</code> (${esc(c.validation_type)}) — ${esc(
              (c.description || "").slice(0, 400)
            )}</li>`
        )
        .join("")}</ul>
      <h4>Validation row</h4>
      <pre class="mono-block">${esc(JSON.stringify(r, null, 2))}</pre>
      <h4>Findings</h4>
      <ul class="plain">${finds.map((f) => `<li><code>${esc(f.finding_id)}</code> — ${esc(f.severity)} — ${esc((f.title || "").slice(0, 120))}</li>`).join("")}</ul>
      <h4>POA&amp;M refs</h4>
      <ul class="plain">${poams.map((p) => `<li><code>${esc(p.poam_id)}</code></li>`).join("") || "<li>—</li>"}</ul>
      <h4>Assessor (KSI-by-KSI excerpt)</h4>
      <div class="md-scroll">${simpleMdToHtml((assessorSec || "—").slice(0, 12000))}</div>
      <h4>Executive / AO (catalog reporting_sections)</h4>
      <p><strong>Executive:</strong> ${esc(rs.executive || "")}</p>
      <p><strong>AO:</strong> ${esc(rs.ao || "")}</p>
    `;
  }

  function renderCrosswalk(state) {
    const el = document.getElementById("20x-crosswalk");
    if (!el) return;
    const pkg = state.twentyx && state.twentyx.package;
    if (!pkg) {
      el.innerHTML = "<p class='warn'>No package.</p>";
      return;
    }
    const r45 = (pkg.control_crosswalk && pkg.control_crosswalk.rev4_to_rev5) || [];
    const r5k = (pkg.control_crosswalk && pkg.control_crosswalk.rev5_to_20x_ksi) || [];
    const cat = catalogById(pkg);
    const res = resultById(state.twentyx);
    const reg = registryById(pkg);
    const r5toKsi = {};
    r5k.forEach((row) => {
      const r5 = row.rev5_control_id;
      const kid = row.ksi_id;
      if (!r5 || !kid) return;
      if (!r5toKsi[r5]) r5toKsi[r5] = new Set();
      r5toKsi[r5].add(String(kid));
    });
    const lines = [];
    r45.forEach((row) => {
      const r4 = row.rev4_control_id;
      const r5 = row.rev5_control_id;
      const ks = [...(r5toKsi[r5] || [])].sort();
      const pushRow = (kid) => {
        const k = cat[kid] || {};
        const src = (k.evidence_sources || []).join(", ");
        const vr = kid && res[kid] ? JSON.stringify({ status: res[kid].status, summary: (res[kid].summary || "").slice(0, 120) }) : "{}";
        lines.push(
          `<tr><td>${esc(r4)}</td><td>${esc(r5)}</td><td>${kid ? `<code>${esc(kid)}</code>` : "—"}</td><td>${esc(src)}</td><td class="mono-cell">${esc(
            vr
          )}</td></tr>`
        );
      };
      if (ks.length) ks.forEach(pushRow);
      else pushRow("");
    });
    el.innerHTML =
      "<table class='data'><thead><tr><th>Rev4</th><th>Rev5</th><th>KSI</th><th>Evidence source ids</th><th>Validation</th></tr></thead><tbody>" +
      (lines.length ? lines.join("") : "<tr><td colspan='5'>No crosswalk rows.</td></tr>") +
      "</tbody></table>";
  }

  function renderEvidenceSources(state) {
    const el = document.getElementById("20x-evidence-sources");
    if (!el) return;
    const pkg = state.twentyx && state.twentyx.package;
    if (!pkg) {
      el.innerHTML = "<p class='warn'>No package.</p>";
      return;
    }
    const reg = registryById(pkg);
    const cat = catalogById(pkg);
    const kidToSources = {};
    Object.keys(cat).forEach((kid) => {
      (cat[kid].evidence_sources || []).forEach((sid) => {
        if (!kidToSources[sid]) kidToSources[sid] = [];
        kidToSources[sid].push(kid);
      });
    });
    const rows = Object.values(reg).map((s) => {
      const ks = (kidToSources[s.id] || []).sort().join(", ");
      return `<tr><td><code>${esc(s.id)}</code></td><td>${esc(s.category)}</td><td>${esc(s.collection_method)}</td><td>${esc(
        s.frequency
      )}</td><td>${esc(s.owner)}</td><td>${esc((s.authoritative_for || []).join(", "))}</td><td>${esc(
        (s.limitations || []).join("; ")
      )}</td><td>${esc(String(s.automation_score))}</td><td class="mono-cell">${esc(ks)}</td></tr>`;
    });
    el.innerHTML =
      "<table class='data'><thead><tr><th>ID</th><th>Category</th><th>Collection</th><th>Frequency</th><th>Owner</th><th>Authoritative for</th><th>Limitations</th><th>Auto score</th><th>Linked KSIs</th></tr></thead><tbody>" +
      rows.join("") +
      "</tbody></table>";
  }

  function renderFindings(state) {
    const el = document.getElementById("20x-findings-cards");
    if (!el) return;
    const fs = (state.twentyx && state.twentyx.findings) || [];
    el.innerHTML = fs
      .map((f) => {
        const po = poamForFinding(state.twentyx, f.finding_id);
        const poamLink = po[0] ? `<a href="#20x-poam">POA&amp;M: <code>${esc(po[0].poam_id)}</code></a>` : "—";
        return `<div class="card finding-card" data-fid="${esc(f.finding_id)}">
        <h4><span class="badge ${badgeClass(f.severity === "critical" || f.severity === "high" ? "FAIL" : "partial")}">${esc(
          f.severity || ""
        )}</span> <code>${esc(f.finding_id)}</code></h4>
        <p><strong>Status:</strong> ${esc(f.status || "")} <strong>KSI:</strong> ${esc(
          (f.linked_ksi_ids || f.ksi_ids || []).join(", ")
        )}</p>
        <p><strong>Controls:</strong> ${esc(JSON.stringify(f.legacy_controls || {}))}</p>
        <p><strong>Affected assets:</strong> ${esc((f.affected_assets || []).join(", "))}</p>
        <p><strong>Risk:</strong> ${esc(f.risk_statement || "")}</p>
        <p><strong>Remediation:</strong> ${esc(f.recommended_remediation || "")}</p>
        <p><strong>Evidence lines:</strong></p><ul class="plain">${(f.evidence || [])
          .slice(0, 8)
          .map((x) => `<li>${esc(String(x))}</li>`)
          .join("")}</ul>
        <p>${poamLink}</p></div>`;
      })
      .join("");
    el.querySelectorAll(".finding-card").forEach((div) => {
      div.addEventListener("click", () => {
        state.twentyx.selectedFindingId = div.getAttribute("data-fid");
        document.querySelectorAll('nav a.nav-item[data-panel="ai"]').forEach((a) => a.click());
        const sub = document.getElementById("ai-subtab-bar");
        const b20 = sub && sub.querySelector('[data-subtab="20x"]');
        if (b20) b20.click();
      });
    });
  }

  function renderAo(state) {
    const el = document.getElementById("20x-ao-md");
    if (!el) return;
    const tx = state.twentyx;
    const md = (tx && tx.aoMd) || "";
    const risks = (tx && tx.findings) || [];
    const openRisk = (f) => {
      const st = String((f && f.status) || "open").toLowerCase();
      if (st === "risk_accepted" || st === "closed" || st === "false_positive") return false;
      const ra = f.risk_acceptance;
      if (ra && typeof ra === "object" && ra.accepted_by) return false;
      return true;
    };
    const hi = risks.filter((f) => {
      const sev = String((f && f.severity) || "").toLowerCase();
      return (sev === "high" || sev === "critical") && openRisk(f);
    });
    const regList =
      "<h3 style='margin-top:1.25rem;font-size:1rem'>Open high / critical findings (residual register)</h3><ul class='plain'>" +
      (hi.length
        ? hi
            .map(
              (f) =>
                `<li><code>${esc(f.finding_id)}</code> — ${esc(f.severity)} — ${esc(
                  (f.title || f.description || "").slice(0, 160)
                )}</li>`
            )
            .join("")
        : "<li>None in package.</li>") +
      "</ul>";
    el.innerHTML = simpleMdToHtml(md) + regList;
  }

  function renderExec(state) {
    const el = document.getElementById("20x-exec-md");
    if (!el) return;
    const tx = state.twentyx;
    const a = simpleMdToHtml((tx && tx.executiveMd) || "");
    const b = (tx && tx.execReadinessMd)
      ? "<h3 style='margin-top:1.25rem;font-size:1rem'>Authorization readiness</h3>" + simpleMdToHtml(tx.execReadinessMd)
      : "";
    el.innerHTML = a + b;
  }

  function renderPoam20x(state) {
    const tb = document.querySelector("#20x-poam-table tbody");
    if (!tb) return;
    const rows = (state.twentyx && state.twentyx.poamItems) || [];
    if (!rows.length) {
      tb.innerHTML = "<tr><td colspan='6'>No POA&amp;M items in package.</td></tr>";
      return;
    }
    tb.innerHTML = rows
      .map(
        (p) =>
          `<tr><td>${esc(p.poam_id || "")}</td><td>${esc(p.finding_id || "")}</td><td>${esc(p.status || "")}</td><td>${esc(
            p.controls || ""
          )}</td><td>${esc((p.weakness_name || "").slice(0, 80))}</td><td>${esc((p.source_eval_id || "").slice(0, 40))}</td></tr>`
      )
      .join("");
  }

  function renderReconciliation(state) {
    const el = document.getElementById("20x-recon-cards");
    if (!el) return;
    const rec = state.twentyx && state.twentyx.reconciliation;
    if (!rec || !Array.isArray(rec.checks)) {
      el.innerHTML = "<p class='warn'>No reconciliation.json (run package build; reconciliation is written under evidence/validation-results/).</p>";
      return;
    }
    el.innerHTML = (rec.checks || [])
      .map((c) => {
        const st = String((c && c.status) || "");
        const up = st.toUpperCase();
        const badge = up === "PASS" ? "PASS" : "FAIL";
        return `<div class="card recon-card"><h4><span class="badge ${badgeClass(badge)}">${esc(
          st
        )}</span> ${esc(c.id || "")}</h4><p>${esc(c.description || "")}</p><p class="mono-block">${esc(
          (c.detail || "").slice(0, 800)
        )}</p></div>`;
      })
      .join("");
  }

  function buildFedramp20xAiPayload(state, mode) {
    const tx = state.twentyx;
    if (!tx || !tx.package) return null;
    const cat = catalogById(tx.package);
    const res = resultById(tx);
    const kid = tx.selectedKsiId;
    const k = kid ? cat[kid] : null;
    const r = kid ? res[kid] : null;
    const finds = kid ? findingsForKsi(tx, kid) : [];
    const fid = tx.selectedFindingId;
    const selFinds = fid ? (tx.findings || []).filter((f) => f.finding_id === fid) : finds.slice(0, 5);
    const poams = [];
    selFinds.forEach((f) => poamForFinding(tx, f.finding_id).forEach((p) => poams.push(p)));
    const firstFinding = selFinds[0] || null;
    const firstPoam = poams[0] || null;
    return {
      mode,
      audience: "assessor",
      selected_ksi: k,
      selected_eval: state.selectedEval,
      selected_finding: firstFinding,
      selected_poam: poams.length > 1 ? poams : firstPoam,
      related_evidence: {
        assessment_summary: state.assessmentSummary,
        control_crosswalk: tx.package.control_crosswalk,
        ksi_validation_row: r,
        package_summary: execMetricsFromPackage(tx.package),
        executive_excerpt: (tx.executiveMd || "").slice(0, 4000),
        ao_excerpt: (tx.aoMd || "").slice(0, 4000),
      },
      related_reconciliation: tx.reconciliation || null,
      related_graph: state.evidenceGraph,
      related_poam: state.poamRows.slice(0, 8),
    };
  }

  async function runFedrampAi(state, mode) {
    const q = document.getElementById("ai-question").value.trim();
    const out = document.getElementById("ai-output");
    const payload = buildFedramp20xAiPayload(state, mode);
    if (!payload) {
      out.textContent = "Load a FedRAMP 20x package first (evidence/package/fedramp20x-package.json).";
      return;
    }
    payload.mode = mode;
    payload.question = q;
    const ctxPreview = JSON.stringify(payload, null, 2).slice(0, 24000);
    const preamble =
      "Instruction: Use only provided artifacts. Do not invent evidence.\n\n";
    try {
      const r = await fetch(API_BASE + "/api/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (r.ok) {
        const j = await r.json();
        out.textContent =
          (j.answer || JSON.stringify(j)) + (j.warnings && j.warnings.length ? "\n\n" + j.warnings.join("\n") : "");
        return;
      }
    } catch (_) {
      /* fall through */
    }
    out.textContent = preamble + "Task mode: " + mode + "\n\n" + ctxPreview + "\n\n(User question: " + (q || "(none)") + ")";
  }

  function wireTwentyx(state) {
    document.querySelectorAll("[data-ai20]").forEach((btn) => {
      if (btn.dataset._osaWired) return;
      btn.dataset._osaWired = "1";
      btn.addEventListener("click", () => runFedrampAi(state, btn.getAttribute("data-ai20")));
    });
    const sub = document.getElementById("ai-subtab-bar");
    if (sub && !sub.dataset.wired) {
      sub.dataset.wired = "1";
      sub.querySelectorAll("button").forEach((b) => {
        b.addEventListener("click", () => {
          const id = b.getAttribute("data-subtab");
          state.twentyx.aiSubtab = id;
          sub.querySelectorAll("button").forEach((x) => x.classList.remove("active"));
          b.classList.add("active");
          document.getElementById("ai-sub-assessment").style.display = id === "assessment" ? "block" : "none";
          document.getElementById("ai-sub-20x").style.display = id === "20x" ? "block" : "none";
        });
      });
    }
  }

  function renderAll(state) {
    renderDashboard(state);
    renderKsiExplorer(state);
    renderCrosswalk(state);
    renderEvidenceSources(state);
    renderFindings(state);
    renderAo(state);
    renderExec(state);
    renderReconciliation(state);
    renderPoam20x(state);
  }

  window.OSAFedRamp20x = { bootstrap, renderAll };
})();
