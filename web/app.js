/**
 * Security Evidence Explorer — vanilla JS.
 * Loads artifacts from ../output/ (sibling of web/) then web/sample-data/.
 */
(function () {
  "use strict";

  const API_BASE = "http://127.0.0.1:8081";

  const state = {
    evalResults: null,
    assessmentSummary: null,
    evidenceGraph: null,
    correlations: null,
    gapMatrix: [],
    poamRows: [],
    poamHeaders: [],
    instrumentationMd: "",
    agentInstrumentationMd: "",
    secureAgentArchMd: "",
    auditorMd: "",
    correlationReportMd: "",
    agentRunTrace: null,
    agentRunSummaryMd: "",
    referenceCoverage: null,
    capabilityInventory: null,
    reasonablenessFindings: null,
    liveCollectionCoverage: null,
    conmonWorkbench: null,
    publicExposureWorkbench: null,
    aiBackendStatus: null,
    packageDiff: null,
    goldenPackage: null,
    goldenMetrics: null,
    goldenEvalResults: null,
    goldenRunLog: [],
    goldenReports: {},
    goldenArtifactHits: [],
    loadMeta: { source: "", errors: [] },
    selectedEval: null,
    selectedGraphKey: null,
    selectedPoamRow: null,
    selectedGoldenReport: "executive-summary.md",
  };

  function artifactUrls(name) {
    if (name.indexOf("golden/") === 0) {
      const rel = name.slice("golden/".length);
      return [
        new URL("../build/assurance-package-demo/" + rel, window.location.href).href,
        new URL("sample-data/golden/" + rel, window.location.href).href,
      ];
    }
    return [
      new URL("../output/" + name, window.location.href).href,
      new URL("sample-data/" + name, window.location.href).href,
    ];
  }

  async function fetchFirstOk(name) {
    const errs = [];
    for (const url of artifactUrls(name)) {
      try {
        const r = await fetch(url, { cache: "no-store" });
        if (r.ok) return { url, r };
        errs.push(url + " → " + r.status);
      } catch (e) {
        errs.push(url + " → " + (e && e.message));
      }
    }
    state.loadMeta.errors.push(name + ": " + errs.join("; "));
    return null;
  }

  function parseCsv(text) {
    const rows = [];
    let i = 0;
    let cur = "";
    let row = [];
    let inQ = false;
    while (i < text.length) {
      const c = text[i];
      if (inQ) {
        if (c === '"' && text[i + 1] === '"') {
          cur += '"';
          i += 2;
          continue;
        }
        if (c === '"') {
          inQ = false;
          i++;
          continue;
        }
        cur += c;
        i++;
        continue;
      }
      if (c === '"') {
        inQ = true;
        i++;
        continue;
      }
      if (c === ",") {
        row.push(cur);
        cur = "";
        i++;
        continue;
      }
      if (c === "\r") {
        i++;
        continue;
      }
      if (c === "\n") {
        row.push(cur);
        rows.push(row);
        row = [];
        cur = "";
        i++;
        continue;
      }
      cur += c;
      i++;
    }
    row.push(cur);
    if (row.some((x) => String(x).length)) rows.push(row);
    return rows;
  }

  function csvToObjects(text) {
    const rows = parseCsv(text.trim());
    if (!rows.length) return [];
    const headers = rows[0].map((h) => h.trim());
    return rows.slice(1).map((cells) => {
      const o = {};
      headers.forEach((h, j) => {
        o[h] = cells[j] != null ? String(cells[j]) : "";
      });
      return o;
    });
  }

  function badgeClass(result) {
    const r = String(result || "").toUpperCase();
    if (r === "PASS") return "pass";
    if (r === "PARTIAL") return "partial";
    if (r === "FAIL") return "fail";
    if (r === "OPEN") return "open";
    return "missing";
  }

  function flattenGraphNodes(graph) {
    if (!graph || !graph.nodes) return [];
    const out = [];
    const nodes = graph.nodes;
    if (Array.isArray(nodes)) {
      nodes.forEach((n, i) => {
        const t = n && n.type != null ? String(n.type) : "node";
        const id = n && n.id != null ? String(n.id) : "n" + i;
        out.push({ key: t + "::" + id, category: t, id, raw: n });
      });
      return out;
    }
    for (const [category, arr] of Object.entries(nodes)) {
      if (!Array.isArray(arr)) continue;
      arr.forEach((item, idx) => {
        const id = item && item.id != null ? String(item.id) : category + "-" + idx;
        out.push({ key: category + "::" + id, category, id, raw: item });
      });
    }
    return out;
  }

  function edgesForNode(graph, key) {
    if (!graph || !Array.isArray(graph.edges)) return [];
    return graph.edges.filter((e) => {
      if (e.from != null && e.to != null) {
        return e.from === key || e.to === key;
      }
      const s = e.source || {};
      const t = e.target || {};
      const parts = key.split("::");
      const cat = parts[0];
      const id = parts.slice(1).join("::");
      return (
        (s.type === cat && String(s.id) === id) || (t.type === cat && String(t.id) === id)
      );
    });
  }

  function neighborSummary(graph, nodeKey) {
    const edges = edgesForNode(graph, nodeKey);
    return edges.map((e) => {
      if (e.from != null && e.to != null) {
        const other = e.from === nodeKey ? e.to : e.from;
        return {
          relationship: e.relationship || "",
          neighbor: other,
          direction: e.from === nodeKey ? "out" : "in",
        };
      }
      const s = e.source || {};
      const t = e.target || {};
      const parts = nodeKey.split("::");
      const cat = parts[0];
      const id = parts.slice(1).join("::");
      const fromHere = s.type === cat && String(s.id) === id;
      const other =
        fromHere && t.type != null && t.id != null
          ? `${t.type}::${t.id}`
          : s.type != null && s.id != null
            ? `${s.type}::${s.id}`
            : "";
      return {
        relationship: e.relationship || "",
        neighbor: other,
        direction: fromHere ? "out" : "in",
      };
    });
  }

  function buildEvidenceChainPreview(graph, startKey, maxDepth) {
    if (!graph || !startKey) return { hops: [] };
    const depth = typeof maxDepth === "number" ? maxDepth : 4;
    const seen = new Set([startKey]);
    const hops = [];
    let frontier = [startKey];
    for (let d = 0; d < depth && frontier.length; d++) {
      const next = [];
      const step = [];
      for (const k of frontier) {
        for (const nb of neighborSummary(graph, k)) {
          step.push({ from: k, to: nb.neighbor, relationship: nb.relationship, direction: nb.direction });
          const target = nb.neighbor;
          if (target && !seen.has(target)) {
            seen.add(target);
            next.push(target);
          }
        }
      }
      if (step.length) hops.push(step);
      frontier = next;
    }
    return { hops };
  }

  const TRACE_RULES = {
    CM8_INVENTORY_RECONCILIATION: {
      rule: "Declared authoritative inventory must reconcile to discovered in-boundary production assets: no duplicate authoritative keys, no rogue high-value assets absent from inventory, and expected attributes consistent with discovery.",
      inputs:
        "declared_inventory.csv (inventory_id, asset_id, name, in_boundary, scanner_required, log_required, expected_*); discovered_assets.json (assets[].asset_id, private_ip, tags/Environment).",
      logic:
        "The evaluator compares declared rows to discovered asset_ids; flags duplicate name or asset_id; flags in-boundary declared rows without a matching discovered record; flags discovered production-class assets missing from inventory; compares expected_private_ip to discovered when both exist.",
      conclusion: "CM8_INVENTORY_RECONCILIATION = FAIL when any reconciliation rule fires; PASS only when all checks clear.",
    },
    RA5_SCANNER_SCOPE_COVERAGE: {
      rule: "Every in-boundary production asset with scanner_required=true must be covered by a scanner target (by asset_id, hostname, or IP), unless explicitly exempt in evidence.",
      inputs: "declared_inventory.csv; discovered_assets.json; scanner_targets.csv (asset_id, hostname, ip, credentialed); scanner_findings.json (for contradictions).",
      logic:
        "Match declared in-boundary assets to targets; verify Nessus (or scanner) targets include asset identifiers; open findings on an asset without target coverage may fail the eval as contradictory evidence.",
      conclusion: "RA5_SCANNER_SCOPE_COVERAGE = FAIL when required coverage is missing or contradicted.",
    },
    AU6_CENTRALIZED_LOG_COVERAGE: {
      rule: "Assets requiring central logging must have an active central log path (recent ingestion), not local-only or stale forwarding.",
      inputs: "declared_inventory.csv (log_required); central_log_sources.json (seen_last_24h, local_only, central_destination, asset_id).",
      logic: "Derives LogSource status from fixture flags; requires active central ingestion for required assets in the assessment window.",
      conclusion: "AU6_CENTRALIZED_LOG_COVERAGE = FAIL when required assets lack active central logs.",
    },
    SI4_ALERT_INSTRUMENTATION: {
      rule: "Risky semantic types must have enabled alert rules with recipients; proof-of-life may require sample or last_fired depending on scenario.",
      inputs: "alert_rules.json (enabled, mapped_semantic_types, recipients, sample_alert_ref, last_fired); cloud_events.json / normalized SecurityEvent types.",
      logic: "Maps events to rules by semantic type; disabled rules or missing recipients fail coverage; some scenarios flag missing sample/last_fired as gaps.",
      conclusion: "SI4_ALERT_INSTRUMENTATION = FAIL when no enabled recipient-backed rule covers the required semantics.",
    },
    CROSS_DOMAIN_EVENT_CORRELATION: {
      rule: "Each correlated risky event must show inventory, scanner, central logging, alerting, and ticket linkage as required by the correlation spec.",
      inputs: "correlations.json (per-row booleans and missing_evidence); evidence from AssessmentBundle.",
      logic: "For each correlation row, verify chain fields; missing_evidence lists drive FAIL reasons.",
      conclusion: "CROSS_DOMAIN_EVENT_CORRELATION = FAIL when any correlation row has missing chain evidence.",
    },
    RA5_EXPLOITATION_REVIEW: {
      rule: "Open High/Critical findings require exploitation-review evidence (log review flag, artifact ref, or linked ticket verification) and sufficient logging posture for review.",
      inputs: "scanner_findings.json (severity, status, exploitation_review); tickets.json (linked_finding_ids, has_verification_evidence); central_log_sources.json.",
      logic: "Checks finding.exploitation_review keys and linked tickets; may require active central logs for the affected asset.",
      conclusion: "RA5_EXPLOITATION_REVIEW = FAIL when review artifacts are absent for qualifying findings.",
    },
    CM3_CHANGE_EVIDENCE_LINKAGE: {
      rule: "Security-relevant events must link to change/incident tickets with SIA, test, approval, deploy, and verification evidence as modeled.",
      inputs: "cloud_events.json / SecurityEvent.event_id; tickets.json (linked_event_ids, linked_asset_ids, boolean evidence flags).",
      logic: "Matches events to tickets; evaluates ticket completeness flags for change discipline.",
      conclusion: "CM3_CHANGE_EVIDENCE_LINKAGE = FAIL when required ticket links or evidence flags are missing.",
    },
    CA5_POAM_STATUS: {
      rule: "When evaluations fail, POA&M rows should be generated or tracked for unresolved weaknesses (CA-5 / CA-7 posture).",
      inputs: "eval_results.json outcomes; poam.csv rows (including POAM-AUTO-*).",
      logic: "Compares fail/partial count to generated POA&M rows and seed rows.",
      conclusion: "CA5_POAM_STATUS = OPEN/PARTIAL/FAIL based on whether POA&M coverage matches gaps.",
    },
  };

  function buildDerivationTrace(ev) {
    if (!ev) return "No evaluation selected.";
    const id = ev.eval_id || ev.evalId;
    const T = TRACE_RULES[id];
    if (!T) {
      return (
        "Derivation trace template not defined for " +
        id +
        ". Use evidence, gaps, and recommended_action from eval_results.json."
      );
    }
    const lines = [
      "Why did this fail (or partial/open)?",
      "",
      "Rule:",
      T.rule,
      "",
      "Inputs (artifact classes):",
      T.inputs,
      "",
      "Matching logic (summary):",
      T.logic,
      "",
      "Conclusion:",
        T.conclusion,
      "",
      "From this run (eval_results.json):",
      "- result: " + (ev.result || ""),
      "- summary: " + (ev.summary || ""),
      "- gap: " + (ev.gap || "").slice(0, 800),
    ];
    return lines.join("\n");
  }

  function simpleMdToHtml(md) {
    if (!md) return "<p class='warn'>No content.</p>";
    let h = escapeHtml(md);
    h = h.replace(/^### (.*)$/gm, "<h3>$1</h3>");
    h = h.replace(/^## (.*)$/gm, "<h2>$1</h2>");
    h = h.replace(/^# (.*)$/gm, "<h1>$1</h1>");
    h = h.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
    h = h.replace(/^- (.*)$/gm, "<li>$1</li>");
    h = h.replace(/(<li>.*<\/li>\n?)+/g, "<ul class='plain'>$&</ul>");
    h = h.replace(/```(\w*)\n([\s\S]*?)```/g, function (_, lang, code) {
      return "<pre><code>" + escapeHtml(code.trim()) + "</code></pre>";
    });
    h = h.replace(/\n\n+/g, "</p><p>");
    return "<div class='md-preview'><p>" + h + "</p></div>";
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function splitInstrumentation(md) {
    const sections = [];
    if (!md) return sections;
    const parts = md.split(/^### /m);
    parts.forEach((block, i) => {
      if (!block.trim()) return;
      const lines = block.trim().split("\n");
      const title = i === 0 && !md.trim().startsWith("###") ? "Overview" : lines[0].trim();
      const body = i === 0 && !md.trim().startsWith("###") ? block.trim() : lines.slice(1).join("\n").trim();
      sections.push({ title, body });
    });
    return sections;
  }

  function chainStatus(v) {
    const x = String(v || "").toUpperCase();
    if (x === "PASS") return { cls: "pass", label: "PASS" };
    if (x === "PARTIAL") return { cls: "partial", label: "PARTIAL" };
    if (x === "FAIL") return { cls: "fail", label: "FAIL" };
    if (x === "OPEN") return { cls: "open", label: "OPEN" };
    return { cls: "missing", label: "MISSING" };
  }

  function renderDashboard() {
    const s = state.assessmentSummary || {};
    const evs = (state.evalResults && state.evalResults.evaluations) || [];
    const failIds = evs.filter((e) => e.result === "FAIL").map((e) => e.eval_id);
    const si = failIds.includes("SI4_ALERT_INSTRUMENTATION");
    const ra = failIds.includes("RA5_SCANNER_SCOPE_COVERAGE");
    const au = failIds.includes("AU6_CENTRALIZED_LOG_COVERAGE");

    const cards = [
      ["Assets assessed", s.assets != null ? s.assets : "—"],
      ["Events normalized", s.events != null ? s.events : "—"],
      ["Findings evaluated", s.findings != null ? s.findings : "—"],
      ["Failed evals", s.eval_fail != null ? s.eval_fail : evs.filter((e) => e.result === "FAIL").length],
      ["Partial evals", s.eval_partial != null ? s.eval_partial : evs.filter((e) => e.result === "PARTIAL").length],
      ["POA&M rows (file)", s.poam_rows_generated != null ? s.poam_rows_generated : state.poamRows.length],
      ["Missing alert coverage (SI-4)", si ? "Yes" : "No"],
      ["Missing scanner coverage (RA-5)", ra ? "Yes" : "No"],
      ["Missing central logs (AU)", au ? "Yes" : "No"],
    ];

    const el = document.getElementById("dashboard-cards");
    el.innerHTML = cards
      .map(
        ([l, v]) =>
          `<div class="card"><div class="label">${escapeHtml(l)}</div><div class="value">${escapeHtml(
            String(v)
          )}</div></div>`
      )
      .join("");

    const ctrlCount = {};
    evs.forEach((e) => {
      if (e.result !== "FAIL") return;
      (e.control_refs || []).forEach((c) => {
        ctrlCount[c] = (ctrlCount[c] || 0) + 1;
      });
    });
    const top = Object.entries(ctrlCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 12);
    document.getElementById("dashboard-controls").innerHTML =
      top.length === 0
        ? "<p class='warn'>No failed evaluations.</p>"
        : "<ul class='plain'>" +
          top.map(([c, n]) => `<li><strong>${escapeHtml(c)}</strong> — ${n} failing eval(s)</li>`).join("") +
          "</ul>";
  }

  let evalFilter = "ALL";
  let evalControlFilter = "";
  let graphTypeFilter = "ALL";

  function renderEvalTable() {
    const evs = (state.evalResults && state.evalResults.evaluations) || [];
    const tb = document.querySelector("#eval-table tbody");
    const filtered = evs.filter((e) => {
      if (evalFilter !== "ALL" && e.result !== evalFilter) return false;
      if (evalControlFilter && !(e.control_refs || []).includes(evalControlFilter)) return false;
      return true;
    });
    tb.innerHTML = filtered
      .map((e) => {
        const sel = state.selectedEval && state.selectedEval.eval_id === e.eval_id ? ' class="selected"' : "";
        return `<tr data-eval-id="${escapeHtml(e.eval_id)}"${sel}><td><span class="badge ${badgeClass(
          e.result
        )}">${escapeHtml(e.result)}</span></td><td>${escapeHtml(e.eval_id)}</td><td>${escapeHtml(
          (e.summary || "").slice(0, 120)
        )}</td></tr>`;
      })
      .join("");
    tb.querySelectorAll("tr").forEach((tr) => {
      tr.addEventListener("click", () => {
        const id = tr.getAttribute("data-eval-id");
        let ev = evs.find((x) => x.eval_id === id) || null;
        const recs = (state.evalResults && state.evalResults.eval_result_records) || [];
        const rec = recs.find((r) => r.eval_id === id);
        if (ev && rec) ev = Object.assign({}, rec, ev);
        else if (rec) ev = rec;
        state.selectedEval = ev;
        document.querySelectorAll("#eval-table tbody tr").forEach((r) => r.classList.remove("selected"));
        tr.classList.add("selected");
        renderEvalDetail();
      });
    });
  }

  function renderEvalDetail() {
    const el = document.getElementById("eval-detail");
    const e = state.selectedEval;
    if (!e) {
      el.innerHTML = "<p class='warn'>Select an evaluation row.</p>";
      return;
    }
    const matrix = matrixRowsForEval(e.eval_id);
    const assessorFindings = Array.isArray(e.assessor_findings) ? e.assessor_findings.filter((x) => x && typeof x === "object") : [];
    const workpaperHtml = assessorFindings.length
      ? assessorFindings
          .map((f) => {
            const steps = Array.isArray(f.remediation_steps) ? f.remediation_steps : [];
            return `<div class="card" style="margin-bottom:0.75rem">
              <div class="label">${escapeHtml(f.finding_id || e.eval_id)}</div>
              <p><strong>Priority:</strong> ${escapeHtml(f.priority || "—")} <span style="color:var(--muted)">Effort: ${escapeHtml(
                f.estimated_effort || "—"
              )}</span></p>
              <p><strong>Current state:</strong> ${escapeHtml(f.current_state || "—")}</p>
              <p><strong>Target state:</strong> ${escapeHtml(f.target_state || "—")}</p>
              <ul class="plain">${steps.map((s) => "<li>" + escapeHtml(String(s)) + "</li>").join("")}</ul>
            </div>`;
          })
          .join("")
      : "<p class='warn'>No assessor workpaper emitted for this evaluation.</p>";
    const matrixHtml = matrix.length
      ? `<div class="mono-block">${escapeHtml(
          JSON.stringify(
            matrix.map((r) => ({
              current_state: r.current_state || "",
              target_state: r.target_state || "",
              priority: r.priority || "",
              estimated_effort: r.estimated_effort || "",
              remediation_steps: r.remediation_steps || "",
            })),
            null,
            2
          )
        )}</div>`
      : "<p class='warn'>No evidence_gap_matrix.csv row loaded for this evaluation.</p>";
    const ga = e.generated_artifacts;
    const arts = Array.isArray(ga) ? ga.join(", ") : typeof ga === "string" ? ga : "—";
    el.innerHTML = `
      <h3 style="margin-top:0">${escapeHtml(e.name || e.eval_id)}</h3>
      <p><span class="badge ${badgeClass(e.result)}">${escapeHtml(e.result)}</span>
      <span style="color:var(--muted)"> severity: ${escapeHtml(e.severity || "")}</span></p>
      <p><strong>Controls:</strong> ${escapeHtml((e.control_refs || []).join(", "))}</p>
      <p><strong>Summary:</strong> ${escapeHtml(e.summary || "")}</p>
      <p><strong>Affected assets:</strong> ${escapeHtml((e.affected_assets || []).join(", ") || "—")}</p>
      <h4>Evidence</h4><ul class="plain">${(e.evidence || [])
        .map((x) => "<li>" + escapeHtml(String(x)) + "</li>")
        .join("")}</ul>
      <h4>Gaps</h4><p>${escapeHtml(e.gap || "")}</p>
      <h4>Assessor workpaper</h4>${workpaperHtml}
      <h4>Gap matrix workpaper row</h4>${matrixHtml}
      <h4>Recommended actions</h4><p>${escapeHtml(e.recommended_action || "")}</p>
      <h4>Generated artifacts</h4><p>${escapeHtml(arts)}</p>
      <h4>Derivation trace</h4>
      <div class="mono-block">${escapeHtml(buildDerivationTrace(e))}</div>
    `;
  }

  function matrixRowsForEval(evalId) {
    if (!evalId) return [];
    return (state.gapMatrix || []).filter((r) => String(r.eval_id || "") === String(evalId));
  }

  function renderGraph() {
    const g = state.evidenceGraph;
    const list = document.getElementById("graph-nodes");
    if (!g) {
      list.innerHTML = "<p class='warn'>No evidence_graph.json</p>";
      return;
    }
    renderGraphFilters();
    renderGraphVisual();
    const nodes = flattenGraphNodes(g).filter((n) => graphTypeFilter === "ALL" || n.category === graphTypeFilter);
    list.innerHTML = nodes
      .map(
        (n) =>
          `<div class="graph-node-item" data-gk="${escapeHtml(n.key)}">[${escapeHtml(
            n.category
          )}] <strong>${escapeHtml(String(n.id || n.raw))}</strong></div>`
      )
      .join("");
    list.querySelectorAll(".graph-node-item").forEach((div) => {
      div.addEventListener("click", () => {
        list.querySelectorAll(".graph-node-item").forEach((d) => d.classList.remove("sel"));
        div.classList.add("sel");
        state.selectedGraphKey = div.getAttribute("data-gk");
        showGraphEdges();
      });
    });
  }

  function renderGraphFilters() {
    const bar = document.getElementById("graph-filter-bar");
    if (!bar || !state.evidenceGraph) return;
    const cats = ["ALL"].concat([...new Set(flattenGraphNodes(state.evidenceGraph).map((n) => n.category))].sort());
    bar.innerHTML = cats
      .map((c) => `<button type="button" class="${c === graphTypeFilter ? "active" : ""}" data-graph-cat="${escapeHtml(c)}">${escapeHtml(c)}</button>`)
      .join("");
    bar.querySelectorAll("[data-graph-cat]").forEach((b) => {
      b.addEventListener("click", () => {
        graphTypeFilter = b.getAttribute("data-graph-cat") || "ALL";
        renderGraph();
      });
    });
  }

  function graphColor(category) {
    const map = {
      asset: "#3d8bfd",
      event: "#f85149",
      scanner_finding: "#d4a72c",
      ticket: "#79c0ff",
      control: "#2ea043",
      ksi: "#a371f7",
      poam_item: "#ff7b72",
      alert_rule: "#56d364",
      log_source: "#ffa657",
    };
    return map[category] || "#8b9bb4";
  }

  function renderGraphVisual() {
    const wrap = document.getElementById("graph-visual");
    const g = state.evidenceGraph;
    if (!wrap || !g) return;
    const nodes = flattenGraphNodes(g)
      .filter((n) => graphTypeFilter === "ALL" || n.category === graphTypeFilter)
      .slice(0, 36);
    if (!nodes.length) {
      wrap.innerHTML = "<p class='warn' style='padding:1rem'>No graph nodes for filter.</p>";
      return;
    }
    const keySet = new Set(nodes.map((n) => n.key));
    const edges = (g.edges || []).filter((e) => keySet.has(e.from) && keySet.has(e.to)).slice(0, 80);
    const width = 900;
    const height = 320;
    const cx = width / 2;
    const cy = height / 2;
    const r = Math.min(width, height) * 0.38;
    const pos = {};
    nodes.forEach((n, i) => {
      const angle = (-Math.PI / 2) + (2 * Math.PI * i) / Math.max(nodes.length, 1);
      pos[n.key] = { x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r };
    });
    const edgeHtml = edges
      .map((e) => {
        const a = pos[e.from];
        const b = pos[e.to];
        if (!a || !b) return "";
        return `<line class="gv-edge" x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}"><title>${escapeHtml(e.relationship || "")}</title></line>`;
      })
      .join("");
    const nodeHtml = nodes
      .map((n) => {
        const p = pos[n.key];
        const label = String(n.id || "").slice(0, 20);
        return `<g class="gv-node" data-gk="${escapeHtml(n.key)}" transform="translate(${p.x.toFixed(1)},${p.y.toFixed(1)})">
          <circle r="13" fill="${graphColor(n.category)}"></circle>
          <text x="18" y="4">${escapeHtml(label)}</text>
          <title>${escapeHtml(n.key)}</title>
        </g>`;
      })
      .join("");
    wrap.innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Evidence graph visualization">${edgeHtml}${nodeHtml}</svg>`;
    wrap.querySelectorAll(".gv-node").forEach((node) => {
      node.addEventListener("click", () => {
        state.selectedGraphKey = node.getAttribute("data-gk");
        document.querySelectorAll(".graph-node-item").forEach((d) => d.classList.toggle("sel", d.getAttribute("data-gk") === state.selectedGraphKey));
        showGraphEdges();
      });
    });
  }

  function showGraphEdges() {
    const g = state.evidenceGraph;
    const detail = document.getElementById("graph-detail");
    if (!g || !state.selectedGraphKey) {
      detail.textContent = "Select a node.";
      return;
    }
    const edges = edgesForNode(g, state.selectedGraphKey);
    const neigh = neighborSummary(g, state.selectedGraphKey);
    const chain = buildEvidenceChainPreview(g, state.selectedGraphKey);
    detail.innerHTML =
      "<pre class=\"mono-block\">" +
      escapeHtml(
        JSON.stringify(
          {
            node: state.selectedGraphKey,
            neighbors: neigh,
            edges,
            evidenceChainPreview: chain,
          },
          null,
          2
        )
      ) +
      "</pre>";
  }

  function primaryCorrelationHtml() {
    const er = state.evalResults;
    if (!er) return "";
    const cid = er.correlation_id || "—";
    const sem = er.semantic_event || er.event || {};
    const ae = er.asset_evidence || {};
    const ch = er.evidence_chain || {};
    const asset = sem.asset_id || "—";
    const lines = [
      `${cid} — ${escapeHtml(String(sem.event_type || ""))} on ${escapeHtml(String(asset))}`,
      "",
      `Event / semantic type: <span class="badge ${badgeClass("PASS")}">PASS</span> (normalized)`,
      `Asset resolved: <span class="badge ${asset && asset !== "—" ? "pass" : "fail"}">${asset && asset !== "—" ? "PASS" : "FAIL"}</span>`,
      `Inventory coverage (declared vs discovered): <span class="badge ${badgeClass(ch.asset_in_inventory)}">${escapeHtml(
        ch.asset_in_inventory || "MISSING"
      )}</span>`,
      `Scanner scope: <span class="badge ${badgeClass(ch.scanner_scope)}">${escapeHtml(ch.scanner_scope || "MISSING")}</span>`,
      `Central log ingestion: <span class="badge ${badgeClass(ch.central_logging)}">${escapeHtml(
        ch.central_logging || "MISSING"
      )}</span>`,
      `Alert instrumentation: <span class="badge ${badgeClass(ch.alert_rule)}">${escapeHtml(
        ch.alert_rule || "MISSING"
      )}</span>`,
      `Change ticket linkage: <span class="badge ${badgeClass(ch.change_ticket)}">${escapeHtml(
        ch.change_ticket || "MISSING"
      )}</span>`,
      `Exploitation review: <span class="badge ${badgeClass(ch.exploitation_review)}">${escapeHtml(
        ch.exploitation_review || "MISSING"
      )}</span>`,
      `POA&M: <span class="badge ${badgeClass(ch.poam_entry)}">${escapeHtml(ch.poam_entry || "MISSING")}</span>`,
      "",
      "Raw asset_evidence flags: " + escapeHtml(JSON.stringify(ae)),
    ];
    return lines.join("<br>");
  }

  function renderCorrelations() {
    document.getElementById("corr-primary").innerHTML = primaryCorrelationHtml();
    const wrap = document.getElementById("corr-timelines");
    const data = state.correlations;
    const rows = (data && data.correlations) || [];
    if (!rows.length) {
      wrap.innerHTML =
        "<p class='warn'>No correlations.json (or empty correlations[]). Primary timeline above uses evidence_chain.</p>";
      return;
    }
    wrap.innerHTML = rows
      .map((row, idx) => {
        const steps = [
          ["Event", row.semantic_type ? "PASS" : "FAIL", escapeHtml(String(row.semantic_type || ""))],
          ["Asset", row.asset_id ? "PASS" : "PARTIAL", escapeHtml(String(row.asset_id || "none"))],
          ["Inventory", row.inventory_covered ? "PASS" : "FAIL", ""],
          ["Scanner scope", row.scanner_covered ? "PASS" : "FAIL", ""],
          ["Central logs", row.central_logging_active ? "PASS" : "FAIL", ""],
          [
            "Alert enabled",
            row.alert_rule_enabled ? "PASS" : "FAIL",
            row.alert_sample_available === false ? " (no sample)" : "",
          ],
          ["Ticket linked", row.linked_ticket_id ? "PASS" : "FAIL", ""],
          ["POA&M", row.poam_item_id ? "PASS" : "OPEN", ""],
        ];
        const timeline = steps
          .map(
            ([name, st, extra]) =>
              `<div class="step"><strong>${escapeHtml(name)}</strong> <span class="badge ${badgeClass(
                st
              )}">${escapeHtml(String(st))}</span> ${extra}</div>`
          )
          .join("");
        const miss = (row.missing_evidence || []).join(", ");
        return `<div class="card" style="margin-bottom:1rem"><h3 style="margin:0 0 0.5rem">#${idx + 1} ${escapeHtml(
          String(row.event_id || "")
        )}</h3><div class="timeline">${timeline}</div><p style="font-size:0.85rem;color:var(--muted)">missing_evidence: ${escapeHtml(
          miss || "—"
        )}</p></div>`;
      })
      .join("");
  }

  function renderControls() {
    const evs = (state.evalResults && state.evalResults.evaluations) || [];
    const byC = {};
    evs.forEach((e) => {
      (e.control_refs || []).forEach((c) => {
        if (!byC[c]) byC[c] = [];
        byC[c].push(e);
      });
    });
    const keys = Object.keys(byC).sort();
    const el = document.getElementById("control-list");
    el.innerHTML = keys
      .map((c) => {
        const list = byC[c]
          .map(
            (e) =>
              `<li><span class="badge ${badgeClass(e.result)}">${escapeHtml(e.result)}</span> ${escapeHtml(
                e.eval_id
              )} — ${escapeHtml((e.summary || "").slice(0, 80))}</li>`
          )
          .join("");
        const poamFor = state.poamRows
          .filter((r) => (r.Controls || r["controls"] || "").includes(c.split("(")[0].trim()))
          .slice(0, 3);
        const poamHtml =
          poamFor.length === 0
            ? ""
            : "<p><strong>POA&amp;M rows (sample):</strong></p><ul class='plain'>" +
              poamFor.map((r) => "<li>" + escapeHtml(r["POA&M ID"] || r.poam_id || "") + "</li>").join("") +
              "</ul>";
        return `<div class="card" style="margin-bottom:0.75rem"><h3 style="margin:0 0 0.35rem">${escapeHtml(
          c
        )}</h3><ul class="plain">${list}</ul>${poamHtml}</div>`;
      })
      .join("");
  }

  function renderAssets() {
    const nodes = flattenGraphNodes(state.evidenceGraph);
    const assetIds = [...new Set(nodes.filter((n) => n.category === "asset").map((n) => n.id))];
    const er = state.evalResults;
    const ae = er && er.asset_evidence;
    const ch = er && er.evidence_chain;
    const primary = er && (er.semantic_event || er.event) && (er.semantic_event || er.event).asset_id;

    const el = document.getElementById("asset-list");
    if (!assetIds.length && !primary) {
      el.innerHTML = "<p class='warn'>No asset nodes in graph.</p>";
      return;
    }
    const ids = assetIds.length ? assetIds : [primary];
    el.innerHTML = ids
      .filter(Boolean)
      .map((aid) => {
        const isPrimary = aid === primary;
        const inv = isPrimary && ae ? (ae.declared_inventory && ae.discovered_cloud_asset ? "Present" : "Mismatch") : "See evals";
        const scan = isPrimary && ch ? ch.scanner_scope : "—";
        const logs = isPrimary && ae ? (ae.central_log_seen_last_24h ? "Active" : "Stale / missing") : "—";
        const alerts = isPrimary && ch ? ch.alert_rule : "—";
        return `<div class="card" style="margin-bottom:0.75rem"><h3 style="margin:0">${escapeHtml(
          aid
        )}</h3>
        <ul class="plain">
          <li>Inventory status: ${escapeHtml(inv)}</li>
          <li>Scanner scope (primary chain): <span class="badge ${badgeClass(scan)}">${escapeHtml(
            String(scan || "—")
          )}</span></li>
          <li>Central logs (primary asset_evidence): ${escapeHtml(logs)}</li>
          <li>Alert coverage (chain): <span class="badge ${badgeClass(alerts)}">${escapeHtml(
            String(alerts || "—")
          )}</span></li>
        </ul></div>`;
      })
      .join("");
  }

  function renderPoam() {
    const thead = document.getElementById("poam-thead");
    const tb = document.querySelector("#poam-table tbody");
    if (!state.poamHeaders.length) {
      thead.innerHTML = "";
      tb.innerHTML = "<tr><td>No poam.csv</td></tr>";
      return;
    }
    thead.innerHTML =
      "<tr>" + state.poamHeaders.map((h) => "<th>" + escapeHtml(h) + "</th>").join("") + "</tr>";
    tb.innerHTML = state.poamRows
      .map((row, i) => {
        return (
          "<tr data-poam-idx='" +
          i +
          "'>" +
          state.poamHeaders.map((h) => "<td>" + escapeHtml(row[h] || "") + "</td>").join("") +
          "</tr>"
        );
      })
      .join("");
    tb.querySelectorAll("tr").forEach((tr) => {
      tr.addEventListener("click", () => {
        const i = parseInt(tr.getAttribute("data-poam-idx"), 10);
        state.selectedPoamRow = state.poamRows[i];
        renderPoamDetail();
      });
    });
  }

  function renderPoamDetail() {
    const d = document.getElementById("poam-detail");
    const r = state.selectedPoamRow;
    if (!r) {
      d.innerHTML = "";
      return;
    }
    const sid = r["Source Eval ID"] || r.source_eval_id || "";
    d.innerHTML =
      "<h4>Selected row</h4><div class='mono-block'>" +
      escapeHtml(JSON.stringify(r, null, 2)) +
      "</div><p>Linked eval: <strong>" +
      escapeHtml(sid) +
      "</strong></p>";
  }

  function renderInstrumentation() {
    const el = document.getElementById("instrumentation-sections");
    const secs = splitInstrumentation(state.instrumentationMd);
    if (!secs.length) {
      el.innerHTML = "<p class='warn'>No instrumentation_plan.md</p>";
      return;
    }
    el.innerHTML =
      '<p><button type="button" id="copy-full-inst">Copy full instrumentation_plan.md</button></p>' +
      secs
        .map((s) => {
          return (
            `<div class="card inst-section" style="margin-bottom:1rem"><h3>${escapeHtml(s.title)}</h3>` +
            `<div class="mono-block">${escapeHtml(s.body)}</div>` +
            `<button type="button" class="copy-inst-section">Copy section</button></div>`
          );
        })
        .join("");
    document.getElementById("copy-full-inst").addEventListener("click", () => {
      navigator.clipboard.writeText(state.instrumentationMd);
    });
    const agentInstEl = document.getElementById("agent-instrumentation-md");
    if (agentInstEl) {
      agentInstEl.innerHTML = state.agentInstrumentationMd
        ? simpleMdToHtml(state.agentInstrumentationMd)
        : "<p class='warn'>No agent_instrumentation_plan.md (run <code>agent.py assess</code> to generate).</p>";
    }
    const copyAgentInst = document.getElementById("copy-full-agent-inst");
    if (copyAgentInst) {
      copyAgentInst.addEventListener("click", () => {
        if (state.agentInstrumentationMd) navigator.clipboard.writeText(state.agentInstrumentationMd);
      });
    }
  }

  function renderSecureAgentArch() {
    const el = document.getElementById("secure-agent-md");
    if (el) el.innerHTML = simpleMdToHtml(state.secureAgentArchMd);
  }

  function renderAgentRun() {
    const sum = document.getElementById("agent-run-summary");
    const stepsEl = document.getElementById("agent-run-steps");
    const raw = document.getElementById("agent-run-trace-raw");
    if (!sum || !stepsEl || !raw) return;
    sum.innerHTML = state.agentRunSummaryMd
      ? simpleMdToHtml(state.agentRunSummaryMd)
      : "<p class='warn'>No agent_run_summary.md — run <code>python agent.py run-agent --provider fixture --scenario scenario_agentic_risk</code>.</p>";
    const tr = state.agentRunTrace;
    if (!tr || !Array.isArray(tr.steps)) {
      stepsEl.innerHTML = "<p class='warn'>No agent_run_trace.json</p>";
      raw.textContent = "";
      return;
    }
    const rows = tr.steps
      .map(function (s) {
        const act = s.chosen_action != null ? String(s.chosen_action) : "—";
        const pol = s.policy && s.policy.allowed === true ? "ALLOW" : s.policy && s.policy.allowed === false ? "DENY" : "—";
        const ver = (s.verification && s.verification.status) || "—";
        const art = String(s.output_artifact || "—").slice(0, 160);
        return (
          "<tr><td>" +
          escapeHtml(String(s.step_index)) +
          "</td><td>" +
          escapeHtml(String(s.phase || "")) +
          "</td><td>" +
          escapeHtml(act) +
          "</td><td>" +
          escapeHtml(pol) +
          "</td><td>" +
          escapeHtml(ver) +
          "</td><td>" +
          escapeHtml(art) +
          "</td></tr>"
        );
      })
      .join("");
    stepsEl.innerHTML =
      "<table class='data'><thead><tr><th>#</th><th>Phase</th><th>Action</th><th>Policy</th><th>Verify</th><th>Artifact</th></tr></thead><tbody>" +
      rows +
      "</tbody></table>";
    raw.textContent = JSON.stringify(tr, null, 2);
    const copyTr = document.getElementById("copy-agent-trace-json");
    if (copyTr && !copyTr._wired) {
      copyTr._wired = true;
      copyTr.addEventListener("click", function () {
        navigator.clipboard.writeText(raw.textContent || "");
      });
    }
  }

  function renderAuditor() {
    document.getElementById("auditor-md").innerHTML = simpleMdToHtml(state.auditorMd);
  }

  function renderCapabilities() {
    const ref = state.referenceCoverage || {};
    const inv = state.capabilityInventory || {};
    const summary = inv.summary || {};
    const cards = [
      ["Reference samples", ref.sample_count || "—"],
      ["Reference projects", ref.project_count || "—"],
      ["Implemented capabilities", summary.implemented != null ? summary.implemented : "—"],
      ["Partial capabilities", summary.partial != null ? summary.partial : "—"],
      ["Planned capabilities", summary.planned != null ? summary.planned : "—"],
    ];
    const cardEl = document.getElementById("capability-cards");
    if (cardEl) {
      cardEl.innerHTML = cards
        .map(([l, v]) => `<div class="card"><div class="label">${escapeHtml(l)}</div><div class="value">${escapeHtml(String(v))}</div></div>`)
        .join("");
    }
    const projects = Array.isArray(ref.projects) ? ref.projects : [];
    const refEl = document.getElementById("reference-coverage-table");
    if (refEl) {
      refEl.innerHTML = projects.length
        ? `<table class="data"><thead><tr><th>Status</th><th>Project</th><th>Samples</th><th>Fuels</th></tr></thead><tbody>${projects
            .map(
              (p) =>
                `<tr><td><span class="badge ${badgeClass(p.status === "implemented" ? "PASS" : p.status === "partial" ? "PARTIAL" : "OPEN")}">${escapeHtml(
                  p.status || "unknown"
                )}</span></td><td>${escapeHtml(p.project || "")}</td><td>${escapeHtml(String(p.samples || ""))}</td><td>${escapeHtml(p.fuels || "")}</td></tr>`
            )
            .join("")}</tbody></table>`
        : "<p class='warn'>No reference_coverage.json loaded.</p>";
    }
    const caps = Array.isArray(inv.capabilities) ? inv.capabilities : [];
    const capEl = document.getElementById("capability-inventory-table");
    if (capEl) {
      capEl.innerHTML = caps.length
        ? `<table class="data"><thead><tr><th>Status</th><th>Capability</th><th>Proof</th></tr></thead><tbody>${caps
            .map(
              (c) =>
                `<tr><td><span class="badge ${badgeClass(c.status === "implemented" ? "PASS" : c.status === "partial" ? "PARTIAL" : "OPEN")}">${escapeHtml(
                  c.status || "unknown"
                )}</span></td><td>${escapeHtml(c.capability || "")}</td><td>${escapeHtml(c.proof || "")}</td></tr>`
            )
            .join("")}</tbody></table>`
        : "<p class='warn'>No capability_inventory.json loaded.</p>";
    }
  }

  function getGoldenPackage() {
    return state.goldenPackage || {};
  }

  function getManifest() {
    return getGoldenPackage().manifest || {};
  }

  function statusBadge(status) {
    const s = String(status || "UNKNOWN").toUpperCase();
    let cls = "missing";
    if (["PASS", "COMPLIANT", "FIXED", "READY_FOR_REVIEW", "APPROVED", "SUCCESS"].includes(s)) cls = "pass";
    else if (["WARN", "PARTIALLY_COMPLIANT", "DRAFT", "NEEDS_HUMAN_REVIEW"].includes(s)) cls = "partial";
    else if (["FAIL", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE", "COLLECTOR_FAILED", "EVIDENCE_UNAVAILABLE"].includes(s)) cls = "fail";
    else if (["OPEN", "RISK_ACCEPTED", "FALSE_POSITIVE", "RETURNED"].includes(s)) cls = "open";
    return `<span class="badge ${cls}">${escapeHtml(s)}</span>`;
  }

  function evidenceIdList(ids) {
    const arr = Array.isArray(ids) ? ids : ids ? [ids] : [];
    if (!arr.length) return "<span class='warn'>No evidence IDs</span>";
    return arr.map((id) => `<code>${escapeHtml(String(id))}</code>`).join(" ");
  }

  function renderGoldenPath() {
    const pkg = getGoldenPackage();
    const m = getManifest();
    const metrics = state.goldenMetrics || {};
    const evals = state.goldenEvalResults || {};
    const el = document.getElementById("golden-path-cards");
    if (!el) return;
    if (!state.goldenPackage) {
      el.innerHTML = "<p class='warn'>No golden path package loaded. Run <code>python agent.py golden-path-demo --output-dir build/assurance-package-demo</code>.</p>";
      return;
    }
    const cards = [
      ["Package", m.packageId || "—"],
      ["Status", m.packageStatus || "—"],
      ["Schema", m.schemaValidation || "—"],
      ["Controls", (m.controlsAssessed || []).length],
      ["Evidence", m.evidenceCount],
      ["Findings", m.findingCount],
      ["AI recommendations", m.aiGeneratedRecommendations],
      ["Human reviewed", m.humanReviewedRecommendations],
      ["Unsupported claims blocked", m.unsupportedClaimsBlockedCount],
      ["Eval pass rate", evals.summary ? `${evals.summary.passed}/${evals.summary.total}` : "—"],
      ["Open HIGH", metrics.high_findings_open != null ? metrics.high_findings_open : "—"],
      ["Stale evidence", metrics.stale_evidence_count != null ? metrics.stale_evidence_count : "—"],
    ];
    el.innerHTML = cards
      .map(([l, v]) => {
        const display = String(v ?? "—").replace(/_/g, " ");
        return `<div class="card"><div class="label">${escapeHtml(String(l))}</div><div class="value fit-value">${escapeHtml(display)}</div></div>`;
      })
      .join("");
    const stages = [
      ["Raw scanner/cloud telemetry", "vulnerability_scan.json + cloud_config.json"],
      ["Normalize", `${(pkg.evidence || []).length} EvidenceArtifact rows, ${(pkg.findings || []).length} NormalizedFinding rows`],
      ["Validate", `${(pkg.validationResults || []).length} deterministic validator results`],
      ["Map controls", `${(pkg.controlMappings || []).length} ControlMapping records`],
      ["RAG context", "bounded source-linked bundles, stale/wrong-scope evidence rejected"],
      ["Recommend", `${(pkg.agentRecommendations || []).length} human-reviewable recommendations`],
      ["Review", `${(pkg.humanReviewDecisions || []).length} immutable reviewer decisions`],
      ["Package", "machine-readable JSON + human-readable Markdown + metrics + evals"],
    ];
    const flow = document.getElementById("golden-path-flow");
    if (flow) {
      flow.innerHTML = stages
        .map(([title, body], i) => `<div class="flow-step"><div class="flow-num">${i + 1}</div><strong>${escapeHtml(title)}</strong><p>${escapeHtml(body)}</p></div>`)
        .join("");
    }
    const art = document.getElementById("golden-path-artifacts");
    if (art) {
      art.innerHTML = state.goldenArtifactHits.length
        ? `<table class="data"><thead><tr><th>Artifact</th><th>Loaded from</th></tr></thead><tbody>${state.goldenArtifactHits
            .map((x) => `<tr><td><code>${escapeHtml(x.name)}</code></td><td>${escapeHtml(x.url)}</td></tr>`)
            .join("")}</tbody></table>`
        : "<p class='warn'>No golden path artifacts loaded.</p>";
    }
  }

  function renderAssurancePackage() {
    const pkg = getGoldenPackage();
    const m = getManifest();
    const cardsEl = document.getElementById("assurance-manifest-cards");
    if (!cardsEl) return;
    if (!state.goldenPackage) {
      cardsEl.innerHTML = "<p class='warn'>No assurance-package.json loaded.</p>";
      return;
    }
    const insufficient = m.controlsWithInsufficientEvidence || [];
    const cards = [
      ["System", m.system || "—"],
      ["Framework", `${m.framework || "—"} / ${m.baseline || "—"}`],
      ["Period", `${(m.assessmentPeriod && m.assessmentPeriod.start) || "—"} → ${(m.assessmentPeriod && m.assessmentPeriod.end) || "—"}`],
      ["Package status", m.packageStatus || "—"],
      ["Schema validation", m.schemaValidation || "—"],
      ["Insufficient evidence", insufficient.length],
    ];
    cardsEl.innerHTML = cards
      .map(([l, v]) => `<div class="card"><div class="label">${escapeHtml(String(l))}</div><div class="value" style="font-size:1rem">${escapeHtml(String(v))}</div></div>`)
      .join("");

    const assessments = pkg.assessmentResults || [];
    const assessmentByControl = {};
    assessments.forEach((a) => {
      assessmentByControl[a.controlId] = a;
    });
    const controls = pkg.controls || [];
    const controlsEl = document.getElementById("assurance-controls");
    if (controlsEl) {
      controlsEl.innerHTML = controls.length
        ? `<table class="data"><thead><tr><th>Status</th><th>Control</th><th>Title</th><th>Evidence IDs</th></tr></thead><tbody>${controls
            .map((c) => {
              const a = assessmentByControl[c.controlId] || {};
              return `<tr><td>${statusBadge(a.status)}</td><td><strong>${escapeHtml(c.controlId || "")}</strong></td><td>${escapeHtml(c.title || "")}</td><td>${evidenceIdList(a.evidenceIds)}</td></tr>`;
            })
            .join("")}</tbody></table>`
        : "<p class='warn'>No controls in package.</p>";
    }
    const validationEl = document.getElementById("assurance-validation");
    if (validationEl) {
      const rows = (pkg.validationResults || []).slice().sort((a, b) => String(a.controlId || "").localeCompare(String(b.controlId || "")));
      validationEl.innerHTML = rows.length
        ? `<table class="data"><thead><tr><th>Status</th><th>Validator</th><th>Control</th><th>Message</th></tr></thead><tbody>${rows
            .map((r) => `<tr><td>${statusBadge(r.status)}</td><td>${escapeHtml(r.validatorId || "")}</td><td>${escapeHtml(r.controlId || "—")}</td><td>${escapeHtml(r.message || "")}</td></tr>`)
            .join("")}</tbody></table>`
        : "<p class='warn'>No validation results.</p>";
    }
    const assessEl = document.getElementById("assurance-assessments");
    if (assessEl) {
      assessEl.innerHTML = assessments.length
        ? `<div class="cards" style="grid-template-columns: repeat(auto-fill, minmax(300px, 1fr))">${assessments
            .map((a) => `<div class="card"><div class="label">${escapeHtml(a.assessmentId || "")}</div><h3 style="margin:0.25rem 0">${escapeHtml(a.controlId || "")} ${statusBadge(a.status)}</h3><p>${escapeHtml(a.summary || "")}</p><p><strong>Confidence:</strong> ${escapeHtml(String(a.confidence ?? "—"))}</p><p><strong>Evidence IDs:</strong> ${evidenceIdList(a.evidenceIds)}</p><p><strong>Gaps:</strong> ${escapeHtml((a.gaps || []).join(" | ") || "—")}</p></div>`)
            .join("")}</div>`
        : "<p class='warn'>No assessment results.</p>";
    }
  }

  function renderAssuranceEvidence() {
    const pkg = getGoldenPackage();
    const evEl = document.getElementById("assurance-evidence-table");
    if (!evEl) return;
    const evidence = pkg.evidence || [];
    evEl.innerHTML = evidence.length
      ? `<table class="data"><thead><tr><th>Freshness</th><th>Evidence ID</th><th>Source</th><th>Account / Region</th><th>Resource</th><th>Controls</th><th>Summary</th></tr></thead><tbody>${evidence
          .map((e) => `<tr><td>${statusBadge(e.freshnessStatus)}</td><td><code>${escapeHtml(e.evidenceId || "")}</code></td><td>${escapeHtml(`${e.sourceSystem || ""} / ${e.sourceType || ""}`)}</td><td>${escapeHtml(`${e.accountId || "—"} / ${e.region || "—"}`)}</td><td>${escapeHtml(e.resourceId || e.resourceArn || "—")}</td><td>${escapeHtml((e.controlIds || []).join(", "))}</td><td>${escapeHtml(e.normalizedSummary || "")}</td></tr>`)
          .join("")}</tbody></table>`
      : "<p class='warn'>No evidence artifacts loaded.</p>";

    const findingsEl = document.getElementById("assurance-findings");
    if (findingsEl) {
      const findings = (pkg.findings || []).slice().sort((a, b) => String(a.severity || "").localeCompare(String(b.severity || "")));
      findingsEl.innerHTML = findings.length
        ? `<div class="cards" style="grid-template-columns: repeat(auto-fill, minmax(320px, 1fr))">${findings
            .map((f) => `<div class="card"><div class="label">${escapeHtml(f.scanner || f.sourceSystem || "")}</div><h3 style="margin:0.25rem 0">${escapeHtml(f.findingId || "")}</h3><p>${statusBadge(f.severity)} ${statusBadge(f.status)}</p><p><strong>${escapeHtml(f.title || "")}</strong></p><p>${escapeHtml(f.description || "")}</p><p><strong>Asset:</strong> ${escapeHtml(f.resourceId || f.imageDigest || "—")}</p><p><strong>Controls:</strong> ${escapeHtml((f.controlIds || []).join(", ") || "—")}</p><p><strong>Evidence IDs:</strong> ${evidenceIdList(f.evidenceIds)}</p></div>`)
            .join("")}</div>`
        : "<p class='warn'>No normalized findings loaded.</p>";
    }
  }

  function renderHumanReview() {
    const pkg = getGoldenPackage();
    const recs = pkg.agentRecommendations || [];
    const decisions = pkg.humanReviewDecisions || [];
    const reviewed = new Set(decisions.map((d) => d.recommendationId));
    const cards = [
      ["Recommendations", recs.length],
      ["Human decisions", decisions.length],
      ["Pending review", recs.filter((r) => !reviewed.has(r.recommendationId)).length],
      ["Compliance-impacting", recs.filter((r) => r.humanReviewRequired).length],
      ["Unsupported claims blocked", recs.filter((r) => r.blockedUnsupportedClaims).length],
    ];
    const cardsEl = document.getElementById("human-review-cards");
    if (cardsEl) {
      cardsEl.innerHTML = cards
        .map(([l, v]) => `<div class="card"><div class="label">${escapeHtml(String(l))}</div><div class="value">${escapeHtml(String(v))}</div></div>`)
        .join("");
    }
    const recEl = document.getElementById("human-review-recommendations");
    if (recEl) {
      recEl.innerHTML = recs.length
        ? `<table class="data"><thead><tr><th>Review</th><th>Type</th><th>Control</th><th>Recommendation</th><th>Evidence IDs</th></tr></thead><tbody>${recs
            .slice(0, 24)
            .map((r) => `<tr><td>${statusBadge(reviewed.has(r.recommendationId) ? "PASS" : "NEEDS_HUMAN_REVIEW")}</td><td>${escapeHtml(r.recommendationType || "")}</td><td>${escapeHtml(r.controlId || "")}</td><td>${escapeHtml(r.summary || "")}</td><td>${evidenceIdList(r.evidenceIds)}</td></tr>`)
            .join("")}</tbody></table>`
        : "<p class='warn'>No agent recommendations loaded.</p>";
    }
    const decEl = document.getElementById("human-review-decisions");
    if (decEl) {
      decEl.innerHTML = decisions.length
        ? `<table class="data"><thead><tr><th>Decision</th><th>Reviewer</th><th>Control</th><th>Recommendation</th><th>Justification</th><th>Evidence IDs</th></tr></thead><tbody>${decisions
            .slice(0, 24)
            .map((d) => `<tr><td>${statusBadge(d.decision)}</td><td>${escapeHtml(d.reviewer || "")}</td><td>${escapeHtml(d.controlId || "")}</td><td><code>${escapeHtml(d.recommendationId || "")}</code></td><td>${escapeHtml(d.justification || "")}</td><td>${evidenceIdList(d.evidenceIds)}</td></tr>`)
            .join("")}</tbody></table>`
        : "<p class='warn'>No human review decisions loaded.</p>";
    }
  }

  function renderMetricsEvals() {
    const metrics = state.goldenMetrics || {};
    const evals = state.goldenEvalResults || {};
    const cards = [
      ["Retrieval hit rate", metrics.retrieval_hit_rate != null ? metrics.retrieval_hit_rate : "—"],
      ["Stale evidence", metrics.stale_evidence_count != null ? metrics.stale_evidence_count : "—"],
      ["Missing evidence", metrics.missing_evidence_count != null ? metrics.missing_evidence_count : "—"],
      ["Unsupported claims", metrics.unsupported_claim_count != null ? metrics.unsupported_claim_count : "—"],
      ["Controls without evidence", metrics.controls_without_evidence != null ? metrics.controls_without_evidence : "—"],
      ["Assets without scan", metrics.assets_without_scan != null ? metrics.assets_without_scan : "—"],
      ["High open", metrics.high_findings_open != null ? metrics.high_findings_open : "—"],
      ["Critical open", metrics.critical_findings_open != null ? metrics.critical_findings_open : "—"],
    ];
    const cardsEl = document.getElementById("metrics-cards");
    if (cardsEl) {
      cardsEl.innerHTML = cards
        .map(([l, v]) => `<div class="card"><div class="label">${escapeHtml(String(l))}</div><div class="value">${escapeHtml(String(v))}</div></div>`)
        .join("");
    }
    const raw = document.getElementById("metrics-json");
    if (raw) raw.textContent = Object.keys(metrics).length ? JSON.stringify(metrics, null, 2) : "No metrics.json loaded.";
    const evalEl = document.getElementById("golden-eval-results");
    if (evalEl) {
      const cases = evals.results || evals.evaluations || [];
      evalEl.innerHTML = cases.length
        ? `<table class="data"><thead><tr><th>Result</th><th>Eval</th><th>Expected / actual</th></tr></thead><tbody>${cases
            .map((e) => `<tr><td>${statusBadge(e.passed === true || e.result === "PASS" ? "PASS" : "FAIL")}</td><td>${escapeHtml(e.evalId || e.eval_id || e.name || "")}</td><td>${escapeHtml((e.summary || e.message || JSON.stringify(e.expected || {})).slice(0, 220))}</td></tr>`)
            .join("")}</tbody></table>`
        : evals.summary
          ? `<div class="mono-block">${escapeHtml(JSON.stringify(evals.summary, null, 2))}</div>`
          : "<p class='warn'>No eval_results.json loaded.</p>";
    }
  }

  function renderReportsLog() {
    const names = [
      "executive-summary.md",
      "control-assessment-report.md",
      "open-risks.md",
      "evidence-table.md",
      "reviewer-decisions.md",
      "eval_summary.md",
    ];
    const tabs = document.getElementById("report-tabs");
    if (tabs) {
      tabs.innerHTML = names
        .map((n) => `<button type="button" class="${n === state.selectedGoldenReport ? "active" : ""}" data-report-name="${escapeHtml(n)}">${escapeHtml(n)}</button>`)
        .join("");
      tabs.querySelectorAll("[data-report-name]").forEach((btn) => {
        btn.addEventListener("click", () => {
          state.selectedGoldenReport = btn.getAttribute("data-report-name") || "executive-summary.md";
          renderReportsLog();
        });
      });
    }
    const report = document.getElementById("selected-report");
    if (report) {
      const text = state.goldenReports[state.selectedGoldenReport] || "";
      report.innerHTML = text ? simpleMdToHtml(text) : "<p class='warn'>Report not loaded.</p>";
    }
    const logEl = document.getElementById("agent-run-log-table");
    if (logEl) {
      const rows = Array.isArray(state.goldenRunLog) ? state.goldenRunLog : [];
      logEl.innerHTML = rows.length
        ? `<table class="data"><thead><tr><th>Status</th><th>Workflow</th><th>Duration</th><th>Schema</th><th>Controls</th><th>Evidence IDs</th><th>Warnings / errors</th></tr></thead><tbody>${rows
            .map((r) => `<tr><td>${statusBadge(r.status)}</td><td>${escapeHtml(r.workflow || "")}</td><td>${escapeHtml(String(r.durationMs ?? "—"))}</td><td>${statusBadge(r.schemaValid === false ? "FAIL" : "PASS")}</td><td>${escapeHtml((r.controlIds || []).join(", ") || "—")}</td><td>${evidenceIdList(r.evidenceIds)}</td><td>${escapeHtml([...(r.warnings || []), ...(r.errors || [])].join(" | ") || "—")}</td></tr>`)
            .join("")}</tbody></table>`
        : "<p class='warn'>No agent-run-log.json loaded.</p>";
    }
  }

  function renderReasonableTest() {
    const doc = state.reasonablenessFindings || {};
    const contract = document.getElementById("reasonable-contract");
    if (contract) contract.textContent = doc.evidence_contract || "No reasonableness_findings.json loaded.";
    const rows = Array.isArray(doc.findings) ? doc.findings : [];
    const el = document.getElementById("reasonable-findings");
    if (!el) return;
    el.innerHTML = rows.length
      ? rows
          .map((f) => {
            const proof = Array.isArray(f.required_proof) ? f.required_proof : [];
            const supplied = Array.isArray(f.supplied_artifacts) ? f.supplied_artifacts : [];
            return `<div class="card" style="margin-top:1rem">
              <div class="label">${escapeHtml(f.gap_type || "")}</div>
              <h3 style="margin:0.25rem 0">${escapeHtml(f.gap_id || "")} <span class="badge ${badgeClass(
                f.sufficiency === "fail" ? "FAIL" : f.sufficiency === "partial" ? "PARTIAL" : "PASS"
              )}">${escapeHtml(f.sufficiency || "unknown")}</span></h3>
              <p><strong>Controls:</strong> ${escapeHtml((f.control_refs || []).join(", "))}</p>
              <p><strong>Reason:</strong> ${escapeHtml(f.reason || "")}</p>
              <div class="split"><div><strong>Required proof</strong><ul class="plain">${proof
                .map((p) => `<li>${escapeHtml(p)}</li>`)
                .join("")}</ul></div><div><strong>Supplied artifacts</strong><ul class="plain">${supplied
                .map((p) => `<li>${escapeHtml(p)}</li>`)
                .join("")}</ul></div></div>
              <p><strong>Remediation:</strong> ${escapeHtml(f.recommended_remediation || "")}</p>
            </div>`;
          })
          .join("")
      : "<p class='warn'>No reasonableness findings loaded.</p>";
  }

  function renderLiveCoverage() {
    const doc = state.liveCollectionCoverage || {};
    const regions = Array.isArray(doc.regions) ? doc.regions : [];
    const success = regions.reduce((n, r) => n + ((r.successful_calls || []).length || 0), 0);
    const denied = regions.reduce((n, r) => n + ((r.denied_calls || []).length || 0), 0);
    const skipped = regions.reduce((n, r) => n + ((r.skipped_services || []).length || 0), 0);
    const cards = [
      ["Provider", doc.provider || "—"],
      ["Regions", regions.length],
      ["Successful calls", success],
      ["Denied calls", denied],
      ["Skipped services", skipped],
    ];
    const cardEl = document.getElementById("live-coverage-cards");
    if (cardEl) {
      cardEl.innerHTML = cards
        .map(([l, v]) => `<div class="card"><div class="label">${escapeHtml(l)}</div><div class="value">${escapeHtml(String(v))}</div></div>`)
        .join("");
    }
    const el = document.getElementById("live-coverage-regions");
    if (!el) return;
    el.innerHTML = regions.length
      ? regions
          .map((r) => {
            const impacts = Array.isArray(r.confidence_impacts) ? r.confidence_impacts : [];
            return `<div class="card" style="margin-bottom:1rem"><h3 style="margin-top:0">${escapeHtml(r.region || "")}</h3>
              <div class="split">
                <div><strong>Successful calls</strong><ul class="plain">${(r.successful_calls || []).map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul></div>
                <div><strong>Denied / skipped</strong><ul class="plain">${(r.denied_calls || []).map((x) => `<li>${escapeHtml(x)}</li>`).join("")}${(r.skipped_services || [])
                .map((x) => `<li>skipped: ${escapeHtml(x)}</li>`)
                .join("")}</ul></div>
              </div>
              <strong>Confidence impact</strong>
              <ul class="plain">${impacts.map((i) => `<li><span class="badge ${badgeClass(i.impact === "low" ? "PASS" : i.impact === "moderate" ? "PARTIAL" : "FAIL")}">${escapeHtml(i.impact || "")}</span> ${escapeHtml(i.eval_id || "")}: ${escapeHtml(i.reason || "")}</li>`).join("")}</ul>
            </div>`;
          })
          .join("")
      : "<p class='warn'>No live_collection_coverage.json loaded.</p>";
  }

  function renderConmonWorkbench() {
    const rows = (state.conmonWorkbench && state.conmonWorkbench.obligations) || [];
    const el = document.getElementById("conmon-workbench");
    if (!el) return;
    el.innerHTML = rows.length
      ? `<table class="data"><thead><tr><th>Coverage</th><th>Control</th><th>Cadence</th><th>Activity</th><th>Last evidence</th><th>Reasonableness gaps</th></tr></thead><tbody>${rows
          .map((r) => `<tr><td><span class="badge ${badgeClass(r.coverage === "gap" ? "FAIL" : r.coverage === "partial" ? "PARTIAL" : "PASS")}">${escapeHtml(r.coverage || "")}</span></td><td>${escapeHtml(r.id || "")}</td><td>${escapeHtml(r.cadence || "")}</td><td>${escapeHtml(r.activity || "")}</td><td>${escapeHtml(r.last_evidence || "")}</td><td>${escapeHtml((r.reasonableness_gaps || []).join(" | "))}</td></tr>`)
          .join("")}</tbody></table>`
      : "<p class='warn'>No conmon_workbench.json loaded.</p>";
  }

  function renderPublicExposureWorkbench() {
    const rows = (state.publicExposureWorkbench && state.publicExposureWorkbench.exposures) || [];
    const el = document.getElementById("public-exposure-workbench");
    if (!el) return;
    el.innerHTML = rows.length
      ? `<div class="cards" style="grid-template-columns: repeat(auto-fill, minmax(280px, 1fr))">${rows
          .map((r) => `<div class="card"><div class="label">${escapeHtml(r.source || "")}</div><h3 style="margin:0.25rem 0">${escapeHtml(r.asset_id || "")}</h3><p><span class="badge ${badgeClass(r.severity === "high" ? "FAIL" : "PARTIAL")}">${escapeHtml(r.severity || "")}</span> ${escapeHtml(r.exposure || "")}</p><p><strong>Status:</strong> ${escapeHtml(r.status || "")}</p><p><strong>Required proof:</strong> ${escapeHtml(r.required_proof || "")}</p></div>`)
          .join("")}</div>`
      : "<p class='warn'>No public_exposure_workbench.json loaded.</p>";
  }

  function renderPackageDiff() {
    const doc = state.packageDiff || {};
    const changes = Array.isArray(doc.changes) ? doc.changes : [];
    const cards = [
      ["Baseline", doc.baseline || "—"],
      ["Current", doc.current || "—"],
      ["Changes", changes.length],
    ];
    const cardEl = document.getElementById("package-diff-cards");
    if (cardEl) {
      cardEl.innerHTML = cards
        .map(([l, v]) => `<div class="card"><div class="label">${escapeHtml(l)}</div><div class="value" style="font-size:1rem">${escapeHtml(String(v))}</div></div>`)
        .join("");
    }
    const el = document.getElementById("package-diff-list");
    if (!el) return;
    el.innerHTML = changes.length
      ? `<ul class="plain">${changes.map((c) => `<li><strong>${escapeHtml(c.type || "")}</strong> ${escapeHtml(c.id || "")}: ${escapeHtml(c.summary || "")}</li>`).join("")}</ul>`
      : "<p class='warn'>No package_diff.json loaded.</p>";
  }

  function renderAiBackendStatus() {
    const doc = state.aiBackendStatus || {};
    const cards = [
      ["Configured backend", doc.configured_backend || "—"],
      ["Last mode", doc.last_reasoning_mode || "—"],
      ["Health", doc.health || "—"],
      ["Supported backends", (doc.supported_backends || []).length || "—"],
    ];
    const cardEl = document.getElementById("ai-backend-cards");
    if (cardEl) {
      cardEl.innerHTML = cards
        .map(([l, v]) => `<div class="card"><div class="label">${escapeHtml(l)}</div><div class="value" style="font-size:1rem">${escapeHtml(String(v))}</div></div>`)
        .join("");
    }
    const contract = document.getElementById("ai-backend-contract");
    if (contract) {
      contract.textContent =
        "Evidence contract:\n" +
        (doc.evidence_contract || "No ai_backend_status.json loaded.") +
        "\n\nSupported backends:\n- " +
        (doc.supported_backends || []).join("\n- ");
    }
  }

  function buildGroundedPrompt(mode, question) {
    const ev = state.selectedEval;
    const rules = [
      "You are explaining a security evidence assessment result.",
      "Rules:",
      "- Use only the provided artifacts.",
      "- Do not invent evidence.",
      "- If evidence is absent, say missing evidence.",
      '- Distinguish "control failed" from "evidence not provided."',
      "- Cite artifact names and fields.",
      "- Explain the derivation step by step.",
      "",
      "User question:",
      question || "(none)",
      "",
      "Task mode:",
      mode,
      "",
      "Selected evaluation (JSON):",
      JSON.stringify(ev || {}, null, 2),
      "",
      "Derivation trace (deterministic):",
      buildDerivationTrace(ev),
      "",
      "Assessment summary:",
      JSON.stringify(state.assessmentSummary || {}, null, 2),
      "",
      "Evidence graph (subset — root_event and edge count):",
      JSON.stringify(
        {
          root_event: state.evidenceGraph && state.evidenceGraph.root_event,
          edge_count: state.evidenceGraph && state.evidenceGraph.edges && state.evidenceGraph.edges.length,
        },
        null,
        2
      ),
      "",
      "Related POA&M rows (first 5):",
      JSON.stringify(state.poamRows.slice(0, 5), null, 2),
    ];
    return rules.join("\n");
  }

  async function runAi(mode) {
    const q = document.getElementById("ai-question").value.trim();
    const out = document.getElementById("ai-output");
    const payload = {
      mode: mode,
      question: q,
      selected_eval: state.selectedEval,
      related_evidence: {
        assessment_summary: state.assessmentSummary,
        correlations: state.correlations,
      },
      related_graph: state.evidenceGraph,
      related_poam: state.poamRows.slice(0, 8),
    };
    try {
      const r = await fetch(API_BASE + "/api/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (r.ok) {
        const j = await r.json();
        out.textContent = (j.answer || JSON.stringify(j)) + (j.warnings && j.warnings.length ? "\n\n" + j.warnings.join("\n") : "");
        return;
      }
    } catch (_) {
      /* fall through */
    }
    out.textContent = buildGroundedPrompt(mode, q);
  }

  document.getElementById("ai-copy-prompt").addEventListener("click", async () => {
    const t = document.getElementById("ai-output").textContent;
    await navigator.clipboard.writeText(t);
  });

  document.querySelectorAll("[data-ai]").forEach((btn) => {
    btn.addEventListener("click", () => runAi(btn.getAttribute("data-ai")));
  });

  function wireNav() {
    document.querySelectorAll("nav a.nav-item").forEach((a) => {
      a.addEventListener("click", (ev) => {
        ev.preventDefault();
        const id = a.getAttribute("data-panel");
        document.querySelectorAll("nav a.nav-item").forEach((x) => x.classList.remove("active"));
        a.classList.add("active");
        document.querySelectorAll("main section.panel").forEach((p) => p.classList.remove("active"));
        const panel = document.getElementById("panel-" + id);
        if (panel) panel.classList.add("active");
      });
    });
  }

  function wireEvalFilters() {
    const wrap = document.getElementById("eval-filters");
    const results = ["ALL", "FAIL", "PARTIAL", "PASS", "OPEN"];
    const controls = [
      "",
      "CM-8",
      "RA-5",
      "AU-6",
      "SI-4",
      "CM-3",
      "CA-5",
      "AU-12",
    ];
    wrap.innerHTML =
      results
        .map(
          (r) =>
            `<button type="button" class="${r === evalFilter ? "active" : ""}" data-rf="${r}">${escapeHtml(
              r
            )}</button>`
        )
        .join("") +
      "<span style='width:1rem'></span>" +
      controls
        .map(
          (c) =>
            `<button type="button" class="${c === evalControlFilter ? "active" : ""}" data-cf="${escapeHtml(
              c
            )}">${c ? "Ctrl: " + c : "All controls"}</button>`
        )
        .join("");
    wrap.querySelectorAll("[data-rf]").forEach((b) => {
      b.addEventListener("click", () => {
        evalFilter = b.getAttribute("data-rf");
        renderEvalTable();
        wireEvalFilters();
      });
    });
    wrap.querySelectorAll("[data-cf]").forEach((b) => {
      b.addEventListener("click", () => {
        evalControlFilter = b.getAttribute("data-cf");
        renderEvalTable();
        wireEvalFilters();
      });
    });
  }

  async function boot() {
    wireNav();
    const loads = [
      ["eval_results.json", "json"],
      ["assessment_summary.json", "json"],
      ["evidence_graph.json", "json"],
      ["correlations.json", "json"],
      ["evidence_gap_matrix.csv", "text"],
      ["poam.csv", "text"],
      ["instrumentation_plan.md", "text"],
      ["agent_instrumentation_plan.md", "text"],
      ["secure_agent_architecture.md", "text"],
      ["auditor_questions.md", "text"],
      ["correlation_report.md", "text"],
      ["agent_run_trace.json", "json"],
      ["agent_run_summary.md", "text"],
      ["reference_coverage.json", "json"],
      ["capability_inventory.json", "json"],
      ["reasonableness_findings.json", "json"],
      ["live_collection_coverage.json", "json"],
      ["conmon_workbench.json", "json"],
      ["public_exposure_workbench.json", "json"],
      ["ai_backend_status.json", "json"],
      ["package_diff.json", "json"],
      ["golden/assurance-package.json", "json"],
      ["golden/metrics.json", "json"],
      ["golden/eval_results.json", "json"],
      ["golden/agent-run-log.json", "json"],
      ["golden/executive-summary.md", "text"],
      ["golden/control-assessment-report.md", "text"],
      ["golden/open-risks.md", "text"],
      ["golden/evidence-table.md", "text"],
      ["golden/reviewer-decisions.md", "text"],
      ["golden/eval_summary.md", "text"],
    ];
    for (const [name, kind] of loads) {
      const hit = await fetchFirstOk(name);
      if (!hit) continue;
      if (name.indexOf("golden/") === 0) state.goldenArtifactHits.push({ name: name.slice("golden/".length), url: hit.url });
      state.loadMeta.source = hit.url;
      if (kind === "json") {
        const j = await hit.r.json();
        if (name === "eval_results.json") state.evalResults = j;
        if (name === "assessment_summary.json") state.assessmentSummary = j;
        if (name === "evidence_graph.json") state.evidenceGraph = j;
        if (name === "correlations.json") state.correlations = j;
        if (name === "agent_run_trace.json") state.agentRunTrace = j;
        if (name === "reference_coverage.json") state.referenceCoverage = j;
        if (name === "capability_inventory.json") state.capabilityInventory = j;
        if (name === "reasonableness_findings.json") state.reasonablenessFindings = j;
        if (name === "live_collection_coverage.json") state.liveCollectionCoverage = j;
        if (name === "conmon_workbench.json") state.conmonWorkbench = j;
        if (name === "public_exposure_workbench.json") state.publicExposureWorkbench = j;
        if (name === "ai_backend_status.json") state.aiBackendStatus = j;
        if (name === "package_diff.json") state.packageDiff = j;
        if (name === "golden/assurance-package.json") state.goldenPackage = j;
        if (name === "golden/metrics.json") state.goldenMetrics = j;
        if (name === "golden/eval_results.json") state.goldenEvalResults = j;
        if (name === "golden/agent-run-log.json") state.goldenRunLog = Array.isArray(j) ? j : [];
      } else if (name.endsWith(".csv")) {
        const t = await hit.r.text();
        const rows = csvToObjects(t);
        if (name === "evidence_gap_matrix.csv") {
          state.gapMatrix = rows;
        } else if (name === "poam.csv") {
          state.poamRows = rows;
          state.poamHeaders = rows.length ? Object.keys(rows[0]) : [];
        }
      } else {
        const t = await hit.r.text();
        if (name === "instrumentation_plan.md") state.instrumentationMd = t;
        if (name === "agent_instrumentation_plan.md") state.agentInstrumentationMd = t;
        if (name === "secure_agent_architecture.md") state.secureAgentArchMd = t;
        if (name === "auditor_questions.md") state.auditorMd = t;
        if (name === "correlation_report.md") state.correlationReportMd = t;
        if (name === "agent_run_summary.md") state.agentRunSummaryMd = t;
        if (name.indexOf("golden/") === 0) state.goldenReports[name.slice("golden/".length)] = t;
      }
    }

    document.getElementById("load-status").textContent = state.evalResults
      ? "Loaded: " + state.loadMeta.source
      : "Failed to load eval_results.json from ../output/ or sample-data/.";

    const evs = (state.evalResults && state.evalResults.evaluations) || [];
    if (evs.length && !state.selectedEval) state.selectedEval = evs[0];

    renderDashboard();
    wireEvalFilters();
    renderEvalTable();
    renderEvalDetail();
    renderGraph();
    if (state.selectedGraphKey == null) {
      const first = document.querySelector(".graph-node-item");
      if (first) {
        state.selectedGraphKey = first.getAttribute("data-gk");
        first.classList.add("sel");
      }
    }
    showGraphEdges();
    renderCorrelations();
    renderControls();
    renderAssets();
    renderPoam();
    renderInstrumentation();
    renderSecureAgentArch();
    document.getElementById("instrumentation-sections").addEventListener("click", (e) => {
      const t = e.target;
      if (t && t.classList && t.classList.contains("copy-inst-section")) {
        const block = t.closest(".inst-section") && t.closest(".inst-section").querySelector(".mono-block");
        if (block) navigator.clipboard.writeText(block.textContent || "");
      }
    });
    renderAuditor();
    renderAgentRun();
    renderCapabilities();
    renderGoldenPath();
    renderAssurancePackage();
    renderAssuranceEvidence();
    renderHumanReview();
    renderMetricsEvals();
    renderReportsLog();
    renderReasonableTest();
    renderLiveCoverage();
    renderConmonWorkbench();
    renderPublicExposureWorkbench();
    renderPackageDiff();
    renderAiBackendStatus();

    if (window.OSAFedRamp20x) {
      await window.OSAFedRamp20x.bootstrap(state);
    }
    if (window.OSATracker) {
      await window.OSATracker.bootstrap(state);
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
