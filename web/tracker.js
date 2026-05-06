/**
 * Tracker → 20x explorer (vanilla JS, no framework).
 *
 * Loads tracker-derived artifacts from one of:
 *   1. ../output_agent_run/                  (default for `run-agent --workflow tracker-to-20x`)
 *   2. ../output_tracker/                    (default for `agent.py tracker-to-20x`)
 *   3. sample-data/tracker/                  (fallback)
 *
 * Renders six tabs: Tracker Import, Evidence Gaps, Agent Run Trace, LLM Reasoning,
 * 20x Package, Derivation Trace.
 */
(function () {
  "use strict";

  const API_BASE = "http://127.0.0.1:8081";

  // Search prefixes for plain artifacts (relative to web/index.html).
  const ARTIFACT_PREFIXES = [
    "../output_agent_run/",
    "../output_tracker/",
    "sample-data/tracker/",
  ];

  // Search prefixes for the 20x package directory.
  const PACKAGE_PREFIXES = [
    "../output_agent_run/package_tracker/",
    "../output_tracker/package_tracker/",
    "../evidence/package_tracker/",
    "sample-data/tracker/package_tracker/",
  ];

  const tracker = {
    rows: [],            // tracker_items.json rows
    rowsSourceUrl: "",
    gapsBundle: null,    // evidence_gaps.json envelope
    informationals: [],
    gaps: [],
    trace: null,         // agent_run_trace.json
    summaryMd: "",       // agent_run_summary.md
    trackerEval: null,   // tracker_gap_eval_results.json
    conmonReasonableness: null,
    package: null,       // fedramp20x-package.json
    poamCsvRows: [],
    trackerPoamCsvRows: [],
    auditorMd: "",
    selectedTaskId: null,
    selectedRowIdx: null,
    selectedGapId: null,
    selectedFindingId: null,
    loadErrors: [],
  };

  function esc(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function badgeClass(result) {
    const r = String(result || "").toUpperCase();
    if (r === "PASS" || r === "SUCCESS") return "pass";
    if (r === "PARTIAL") return "partial";
    if (r === "FAIL" || r === "FAILED") return "fail";
    if (r === "OPEN" || r === "BLOCKED") return "open";
    if (r === "SKIPPED") return "missing";
    return "missing";
  }

  function severityBadge(sev) {
    const s = String(sev || "").toLowerCase();
    if (s === "critical") return "fail";
    if (s === "high") return "fail";
    if (s === "moderate" || s === "medium") return "partial";
    if (s === "low") return "open";
    return "missing";
  }

  async function fetchFirstOk(name, prefixes) {
    const errors = [];
    for (const prefix of prefixes) {
      const url = new URL(prefix + name, window.location.href).href;
      try {
        const r = await fetch(url, { cache: "no-store" });
        if (r.ok) return { url, response: r };
        errors.push(url + " → " + r.status);
      } catch (e) {
        errors.push(url + " → " + (e && e.message));
      }
    }
    tracker.loadErrors.push(name + " (not found): " + errors.join("; "));
    return null;
  }

  function parseCsv(text) {
    const rows = [];
    let cur = "";
    let row = [];
    let inQ = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (inQ) {
        if (c === '"' && text[i + 1] === '"') { cur += '"'; i++; continue; }
        if (c === '"') { inQ = false; continue; }
        cur += c; continue;
      }
      if (c === '"') { inQ = true; continue; }
      if (c === ",") { row.push(cur); cur = ""; continue; }
      if (c === "\r") { continue; }
      if (c === "\n") { row.push(cur); rows.push(row); row = []; cur = ""; continue; }
      cur += c;
    }
    if (cur.length || row.length) { row.push(cur); rows.push(row); }
    return rows;
  }

  function csvToObjects(text) {
    const rows = parseCsv(String(text || "").trim());
    if (!rows.length) return [];
    const headers = rows[0].map(h => String(h).trim());
    return rows.slice(1).map(cells => {
      const o = {};
      headers.forEach((h, j) => { o[h] = cells[j] != null ? String(cells[j]) : ""; });
      return o;
    });
  }

  function uniqueSorted(arr) {
    return [...new Set(arr.filter(Boolean))].sort();
  }

  // -------------------------------------------------------------------------
  // Boot loader
  // -------------------------------------------------------------------------

  async function loadAll() {
    const loaders = [
      ["scenario_from_tracker/tracker_items.json", "json", "rows"],
      ["scenario_from_tracker/evidence_gaps.json", "json", "gapsBundle"],
      ["scenario_from_tracker/auditor_questions.md", "text", "auditorMd"],
      ["agent_run_trace.json", "json", "trace"],
      ["agent_run_summary.md", "text", "summaryMd"],
      ["tracker_gap_eval_results.json", "json", "trackerEval"],
      ["conmon_reasonableness.json", "json", "conmonReasonableness"],
      ["poam.csv", "text-csv", "poamCsvRows"],
      ["tracker_poam.csv", "text-csv", "trackerPoamCsvRows"],
    ];
    for (const [name, kind, field] of loaders) {
      const hit = await fetchFirstOk(name, ARTIFACT_PREFIXES);
      if (!hit) continue;
      if (kind === "json") {
        try {
          const j = await hit.response.json();
          if (field === "rows") {
            tracker[field] = (j && (j.rows || j.tracker_items)) || [];
            tracker.rowsSourceUrl = hit.url;
          } else {
            tracker[field] = j;
          }
        } catch (e) {
          tracker.loadErrors.push(name + ": JSON parse failed (" + e.message + ")");
        }
      } else if (kind === "text-csv") {
        const t = await hit.response.text();
        tracker[field] = csvToObjects(t);
      } else {
        tracker[field] = await hit.response.text();
      }
    }

    // Package separately (different prefix set).
    const pkgHit = await fetchFirstOk("fedramp20x-package.json", PACKAGE_PREFIXES);
    if (pkgHit) {
      try {
        tracker.package = await pkgHit.response.json();
      } catch (e) {
        tracker.loadErrors.push("fedramp20x-package.json: " + e.message);
      }
    }

    // Compute derived collections.
    if (tracker.gapsBundle) {
      tracker.gaps = tracker.gapsBundle.evidence_gaps || tracker.gapsBundle.gaps || [];
      tracker.informationals = tracker.gapsBundle.informational_tracker_items || [];
    }
    if (!tracker.conmonReasonableness) {
      const conmonHit = await fetchFirstOk("conmon_reasonableness/conmon_reasonableness.json", ["../output/"]);
      if (conmonHit) {
        try {
          tracker.conmonReasonableness = await conmonHit.response.json();
        } catch (e) {
          tracker.loadErrors.push("conmon_reasonableness.json: " + e.message);
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Tab 1: Tracker Import
  // -------------------------------------------------------------------------

  const importFilters = { control: "", owner: "", status: "", category: "" };

  function renderTrackerImportFilters() {
    const wrap = document.getElementById("tracker-import-filters");
    if (!wrap) return;
    const controls = uniqueSorted(tracker.rows.flatMap(r => r.controls || []));
    const owners = uniqueSorted(tracker.rows.map(r => r.owner));
    const statuses = uniqueSorted(tracker.rows.map(r => r.status));
    const cats = uniqueSorted(tracker.rows.map(r => r.category));

    function dropdown(label, key, options) {
      return (
        '<label style="display:flex;align-items:center;gap:0.35rem;font-size:0.8rem;color:var(--muted)">' +
        esc(label) + ':<select data-filter="' + esc(key) + '">' +
        '<option value="">all</option>' +
        options.map(v => '<option value="' + esc(v) + '"' + (importFilters[key] === v ? " selected" : "") + '>' + esc(v) + '</option>').join("") +
        '</select></label>'
      );
    }
    wrap.innerHTML =
      dropdown("control", "control", controls) +
      dropdown("owner", "owner", owners) +
      dropdown("status", "status", statuses) +
      dropdown("category", "category", cats);
    wrap.querySelectorAll("select").forEach(sel => {
      sel.addEventListener("change", () => {
        importFilters[sel.getAttribute("data-filter")] = sel.value;
        renderTrackerImportTable();
      });
    });
  }

  function rowMatchesImportFilter(r) {
    if (importFilters.control && !(r.controls || []).includes(importFilters.control)) return false;
    if (importFilters.owner && r.owner !== importFilters.owner) return false;
    if (importFilters.status && r.status !== importFilters.status) return false;
    if (importFilters.category && r.category !== importFilters.category) return false;
    return true;
  }

  function renderTrackerImportTable() {
    const tb = document.querySelector("#tracker-import-table tbody");
    if (!tb) return;
    if (!tracker.rows.length) {
      tb.innerHTML = "<tr><td colspan='6' class='warn'>No tracker_items.json found. Run <code>python agent.py run-agent --workflow tracker-to-20x</code>.</td></tr>";
      return;
    }
    tb.innerHTML = tracker.rows
      .filter(rowMatchesImportFilter)
      .map(r => {
        const sel = tracker.selectedRowIdx === r.row_index ? " selected" : "";
        return (
          "<tr class='" + sel + "' data-row-idx='" + esc(r.row_index) + "'>" +
          "<td>" + esc(r.row_index) + "</td>" +
          "<td>" + esc(r.status || "—") + "</td>" +
          "<td>" + esc(r.category || "—") + "</td>" +
          "<td>" + esc((r.controls || []).join(", ")) + "</td>" +
          "<td>" + esc(r.owner || "—") + "</td>" +
          "<td>" + esc(String(r.request_text || "").slice(0, 90)) + "</td>" +
          "</tr>"
        );
      })
      .join("");
    tb.querySelectorAll("tr[data-row-idx]").forEach(tr => {
      tr.addEventListener("click", () => {
        tracker.selectedRowIdx = parseInt(tr.getAttribute("data-row-idx"), 10);
        renderTrackerImportTable();
        renderTrackerImportDetail();
      });
    });
  }

  function classificationForRow(rowIdx) {
    return (tracker.gaps || []).find(g => String(g.source_item_id) === String(rowIdx))
        || (tracker.informationals || []).find(i => String(i.source_item_id) === String(rowIdx))
        || null;
  }

  function renderTrackerImportDetail() {
    const el = document.getElementById("tracker-import-detail");
    if (!el) return;
    const r = tracker.rows.find(x => x.row_index === tracker.selectedRowIdx);
    if (!r) {
      el.innerHTML = "<p class='warn'>Select a row to see the original text + classification.</p>";
      return;
    }
    const cls = classificationForRow(r.row_index);
    el.innerHTML =
      "<h3 style='margin-top:0'>Tracker row #" + esc(r.row_index) + "</h3>" +
      "<p><strong>Controls:</strong> " + esc((r.controls || []).join(", ") || "—") + "</p>" +
      "<p><strong>Owner:</strong> " + esc(r.owner || "—") + " · <strong>Status:</strong> " + esc(r.status || "—") +
      " · <strong>Category:</strong> " + esc(r.category || "—") + "</p>" +
      "<p><strong>Request date:</strong> " + esc(r.request_date || "—") + " · <strong>Due:</strong> " + esc(r.due_date || "—") + "</p>" +
      "<h4>Original request text</h4>" +
      "<div class='mono-block'>" + esc(r.request_text || "") + "</div>" +
      (r.assessor_comment
        ? ("<h4>Assessor comment</h4><div class='mono-block'>" + esc(r.assessor_comment) + "</div>")
        : "") +
      (r.csp_comment
        ? ("<h4>CSP comment</h4><div class='mono-block'>" + esc(r.csp_comment) + "</div>")
        : "") +
      "<h4>Classification signals</h4>" +
      "<div class='mono-block'>" + esc((r.classification_signals || []).join(", ") || "(none)") + "</div>" +
      "<h4>Classifier output</h4>" +
      (cls
        ? ("<div class='mono-block'>" + esc(JSON.stringify(cls, null, 2)) + "</div>")
        : "<p class='warn'>No EvidenceGap or InformationalTrackerItem matched this row.</p>");
  }

  // -------------------------------------------------------------------------
  // Tab 2: Evidence Gaps
  // -------------------------------------------------------------------------

  const gapFilters = { gap_type: "", severity: "", control: "", poam_required: "" };

  function renderGapFilters() {
    const wrap = document.getElementById("tracker-gaps-filters");
    if (!wrap) return;
    const types = uniqueSorted(tracker.gaps.map(g => g.gap_type));
    const sevs = uniqueSorted(tracker.gaps.map(g => g.severity));
    const controls = uniqueSorted(tracker.gaps.flatMap(g => g.controls || []));
    function dropdown(label, key, options) {
      return (
        '<label style="display:flex;align-items:center;gap:0.35rem;font-size:0.8rem;color:var(--muted)">' +
        esc(label) + ':<select data-gap-filter="' + esc(key) + '">' +
        '<option value="">all</option>' +
        options.map(v => '<option value="' + esc(v) + '"' + (gapFilters[key] === v ? " selected" : "") + '>' + esc(v) + '</option>').join("") +
        '</select></label>'
      );
    }
    wrap.innerHTML =
      dropdown("gap_type", "gap_type", types) +
      dropdown("severity", "severity", sevs) +
      dropdown("control", "control", controls) +
      '<label style="display:flex;align-items:center;gap:0.35rem;font-size:0.8rem;color:var(--muted)">poam_required:' +
      '<select data-gap-filter="poam_required"><option value="">all</option>' +
      '<option value="true"' + (gapFilters.poam_required === "true" ? " selected" : "") + '>true</option>' +
      '<option value="false"' + (gapFilters.poam_required === "false" ? " selected" : "") + '>false</option>' +
      '</select></label>';
    wrap.querySelectorAll("select").forEach(sel => {
      sel.addEventListener("change", () => {
        gapFilters[sel.getAttribute("data-gap-filter")] = sel.value;
        renderGapTable();
      });
    });
  }

  function gapMatchesFilter(g) {
    if (gapFilters.gap_type && g.gap_type !== gapFilters.gap_type) return false;
    if (gapFilters.severity && g.severity !== gapFilters.severity) return false;
    if (gapFilters.control && !(g.controls || []).includes(gapFilters.control)) return false;
    if (gapFilters.poam_required) {
      const want = gapFilters.poam_required === "true";
      if (Boolean(g.poam_required) !== want) return false;
    }
    return true;
  }

  function renderGapTable() {
    const tb = document.querySelector("#tracker-gaps-table tbody");
    if (!tb) return;
    if (!tracker.gaps.length) {
      tb.innerHTML = "<tr><td colspan='5' class='warn'>No evidence_gaps.json found.</td></tr>";
      return;
    }
    tb.innerHTML = tracker.gaps
      .filter(gapMatchesFilter)
      .map(g => {
        const sel = tracker.selectedGapId === g.gap_id ? " selected" : "";
        return (
          "<tr class='" + sel + "' data-gap-id='" + esc(g.gap_id) + "'>" +
          "<td><span class='badge " + severityBadge(g.severity) + "'>" + esc(g.severity || "—") + "</span></td>" +
          "<td>" + esc(g.gap_id) + "</td>" +
          "<td>" + esc(g.gap_type) + "</td>" +
          "<td>" + esc((g.controls || []).join(", ")) + "</td>" +
          "<td>" + (g.poam_required ? "yes" : "no") + "</td>" +
          "</tr>"
        );
      })
      .join("");
    tb.querySelectorAll("tr[data-gap-id]").forEach(tr => {
      tr.addEventListener("click", () => {
        tracker.selectedGapId = tr.getAttribute("data-gap-id");
        renderGapTable();
        renderGapDetail();
      });
    });
  }

  function renderGapDetail() {
    const el = document.getElementById("tracker-gaps-detail");
    if (!el) return;
    const g = tracker.gaps.find(x => x.gap_id === tracker.selectedGapId);
    if (!g) {
      el.innerHTML = "<p class='warn'>Select an evidence gap.</p>";
      return;
    }
    const ksiList = (g.linked_ksi_ids || []).join(", ") || "—";
    el.innerHTML =
      "<h3 style='margin-top:0'>" + esc(g.gap_id) + "</h3>" +
      "<p><span class='badge " + severityBadge(g.severity) + "'>" + esc(g.severity || "—") + "</span> " +
      "<span class='badge " + (g.poam_required ? "fail" : "missing") + "'>POA&amp;M " + (g.poam_required ? "required" : "not required") + "</span></p>" +
      "<p><strong>Title:</strong> " + esc(g.title || "—") + "</p>" +
      "<p><strong>Type:</strong> <code>" + esc(g.gap_type) + "</code></p>" +
      "<p><strong>Controls:</strong> " + esc((g.controls || []).join(", ") || "—") + "</p>" +
      "<p><strong>Linked KSIs:</strong> " + esc(ksiList) + "</p>" +
      "<p><strong>Recommended artifact:</strong> <code>" + esc(g.recommended_artifact || "—") + "</code></p>" +
      "<p><strong>Recommended validation:</strong> <code>" + esc(g.recommended_validation || "—") + "</code></p>" +
      "<p><strong>Owner:</strong> " + esc(g.owner || "—") + " · <strong>Status:</strong> " + esc(g.status || "—") +
      " · <strong>Due:</strong> " + esc(g.due_date || "—") + "</p>" +
      "<h4>Description</h4>" +
      "<div class='mono-block'>" + esc(g.description || "") + "</div>" +
      (g.assessor_comment
        ? ("<h4>Assessor comment</h4><div class='mono-block'>" + esc(g.assessor_comment) + "</div>")
        : "") +
      "<p><strong>Source row:</strong> tracker_items[" + esc(g.source_item_id) +
      "] in <code>" + esc(g.source_file) + "</code></p>";
  }

  // -------------------------------------------------------------------------
  // Tab 3: Agent Run Trace (categorical 15-task DAG)
  // -------------------------------------------------------------------------

  function renderTrace() {
    const overall = document.getElementById("tracker-trace-overall");
    const dag = document.getElementById("tracker-trace-dag");
    const tb = document.querySelector("#tracker-trace-table tbody");
    if (!overall || !dag || !tb) return;

    const tr = tracker.trace;
    if (!tr) {
      overall.innerHTML = "<p class='warn'>No agent_run_trace.json — run <code>python agent.py run-agent --workflow tracker-to-20x</code>.</p>";
      dag.innerHTML = "";
      tb.innerHTML = "";
      return;
    }
    const tasks = tr.tasks || [];
    const cards = [
      ["Workflow", tr.workflow || "—"],
      ["Overall status", tr.overall_status || "—"],
      ["Tasks total", tasks.length],
      ["Success", tasks.filter(t => t.status === "success").length],
      ["Skipped", tasks.filter(t => t.status === "skipped").length],
      ["Failed", tasks.filter(t => t.status === "failed").length],
      ["Halted by", tr.halted_by || "—"],
      ["Started", tr.started_at || "—"],
    ];
    overall.innerHTML = cards
      .map(([l, v]) =>
        '<div class="card"><div class="label">' + esc(l) + '</div><div class="value" style="font-size:0.95rem;font-family:var(--mono)">' + esc(String(v)) + '</div></div>'
      )
      .join("");

    dag.innerHTML = tasks
      .map((t, i) => {
        const cls = String(t.status || "").toLowerCase();
        const sel = tracker.selectedTaskId === t.task_id ? " sel" : "";
        const arrow = i < tasks.length - 1 ? '<div class="dag-arrow">→</div>' : "";
        return (
          '<div class="dag-node ' + esc(cls) + sel + '" data-task-id="' + esc(t.task_id) + '">' +
          '<div class="name">' + esc(t.task_id) + '</div>' +
          '<div class="meta">' + esc(t.action_category || "—") + " · " + esc(t.status || "—") + '</div>' +
          '</div>' + arrow
        );
      })
      .join("");
    dag.querySelectorAll(".dag-node").forEach(n => {
      n.addEventListener("click", () => {
        tracker.selectedTaskId = n.getAttribute("data-task-id");
        renderTrace();
        renderTraceDetail();
      });
    });

    tb.innerHTML = tasks
      .map((t, i) => {
        const sel = tracker.selectedTaskId === t.task_id ? " selected" : "";
        const polCat = (t.policy_decision && t.policy_decision.category) || "—";
        const polAllow = t.policy_decision && t.policy_decision.allowed ? "ALLOW" : "DENY";
        return (
          "<tr class='" + sel + "' data-task-id='" + esc(t.task_id) + "'>" +
          "<td>" + esc(i + 1) + "</td>" +
          "<td><code>" + esc(t.task_id) + "</code></td>" +
          "<td>" + esc(t.action_category || "—") + "</td>" +
          "<td><span class='badge " + badgeClass(t.status) + "'>" + esc(t.status || "—") + "</span></td>" +
          "<td>" + esc(polAllow) + " · " + esc(polCat) + "</td>" +
          "</tr>"
        );
      })
      .join("");
    tb.querySelectorAll("tr[data-task-id]").forEach(tr2 => {
      tr2.addEventListener("click", () => {
        tracker.selectedTaskId = tr2.getAttribute("data-task-id");
        renderTrace();
        renderTraceDetail();
      });
    });
  }

  function renderTraceDetail() {
    const el = document.getElementById("tracker-trace-detail");
    if (!el) return;
    const tr = tracker.trace;
    const t = tr && (tr.tasks || []).find(x => x.task_id === tracker.selectedTaskId);
    if (!t) {
      el.innerHTML = "<p class='warn'>Select a task.</p>";
      return;
    }
    const arts = (t.artifacts || []).map(a =>
      "<li><code>" + esc(a.name) + "</code> — <span class='deriv-body'>" + esc(a.path) + "</span></li>"
    ).join("");
    el.innerHTML =
      "<h3 style='margin-top:0'><code>" + esc(t.task_id) + "</code></h3>" +
      "<p>" + esc(t.description || "") + "</p>" +
      "<p><span class='badge " + badgeClass(t.status) + "'>" + esc(t.status || "—") + "</span> " +
      "<span class='badge " + (t.policy_decision && t.policy_decision.allowed ? "pass" : "fail") + "'>" +
      "policy: " + esc((t.policy_decision && t.policy_decision.category) || "—") + "</span></p>" +
      "<p><strong>action_id:</strong> <code>" + esc(t.action_id || "—") + "</code></p>" +
      "<p><strong>depends_on:</strong> " + esc((t.depends_on || []).join(", ") || "—") + "</p>" +
      "<p><strong>started_at:</strong> " + esc(t.started_at || "—") + " · " +
      "<strong>completed_at:</strong> " + esc(t.completed_at || "—") + "</p>" +
      "<p><strong>policy_decision:</strong></p>" +
      "<div class='mono-block'>" + esc(JSON.stringify(t.policy_decision || {}, null, 2)) + "</div>" +
      "<p><strong>inputs:</strong></p>" +
      "<div class='mono-block'>" + esc(JSON.stringify(t.inputs || {}, null, 2)) + "</div>" +
      "<p><strong>outputs:</strong></p>" +
      "<div class='mono-block'>" + esc(JSON.stringify(t.outputs || {}, null, 2)) + "</div>" +
      "<p><strong>artifacts:</strong></p>" +
      "<ul class='plain'>" + (arts || "<li>(none)</li>") + "</ul>" +
      (t.errors && t.errors.length
        ? "<p><strong>errors:</strong></p><div class='mono-block'>" + esc(t.errors.join("\n")) + "</div>"
        : "");
  }

  // -------------------------------------------------------------------------
  // Tab 4: LLM Reasoning
  // -------------------------------------------------------------------------

  // Static copy of core/evidence_contract.py:EVIDENCE_CONTRACT_MARKDOWN — kept
  // verbatim so reviewers can verify the reasoner contract without leaving the page.
  const EVIDENCE_CONTRACT_MD = (
    "## Evidence contract (binding)\n" +
    "\n" +
    "1. **Artifact names:** Every substantive claim must name the artifact or structured field it rests on " +
    "(for example `eval_results.json`, `correlations.json`, `alert_rules.json`, `tickets.json`, " +
    "`scanner_findings.json`, `fedramp20x-package.json`).\n" +
    "2. **Missing evidence:** If a required artifact, field, linkage, or proof object is absent from the " +
    "provided payload, say exactly **missing evidence**. Do not soften into \u201Clikely fine\u201D or " +
    "\u201Ccontrol implemented.\u201D\n" +
    "3. **No gap-to-pass inversion:** Never treat **missing evidence** as proof that a control is " +
    "implemented, effective, or passing.\n" +
    "4. **Alerts / firing:** Never state or imply that an alert **fired** unless `sample_alert_ref` " +
    "and/or explicit firing/event evidence appears in the provided structured inputs.\n" +
    "5. **Tickets:** Never invent or assert a concrete ticket identifier unless `linked_ticket_id` (or " +
    "an equivalent field) is present in the provided payload or an included `tickets.json` slice.\n" +
    "6. **Exploitation review:** Never claim exploitation review was completed unless `scanner_findings.json` " +
    "(or package finding) shows exploitation-review fields.\n"
  );

  const REASONERS = [
    { id: "explain_for_assessor", label: "Explain selected eval (assessor)" },
    { id: "explain_for_executive", label: "Executive summary" },
    { id: "explain_conmon_reasonableness", label: "ConMon reasonableness" },
    { id: "explain_residual_risk_for_ao", label: "AO residual risk" },
    { id: "explain_derivation_trace", label: "Explain derivation trace" },
    { id: "draft_remediation_ticket", label: "Draft remediation ticket" },
    { id: "draft_auditor_response", label: "Draft auditor response" },
    { id: "classify_ambiguous_row", label: "Classify ambiguous row" },
    { id: "evaluate_3pao_remediation_for_gap", label: "Evaluate 3PAO remediation" },
  ];

  function simpleMd(md) {
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

  function selectedFindingForLlm() {
    if (!tracker.package || !tracker.package.findings) return null;
    if (tracker.selectedFindingId) {
      return tracker.package.findings.find(f => f.finding_id === tracker.selectedFindingId)
          || tracker.package.findings[0]
          || null;
    }
    return tracker.package.findings[0] || null;
  }

  function payloadForReasoner(name) {
    const evals = (tracker.trackerEval && (tracker.trackerEval.evaluations || [])) || [];
    const someEval = (function () {
      try {
        const er = window.OSAState && window.OSAState.evalResults;
        if (er && er.evaluations) return er.evaluations[0];
      } catch (_) { /* ignore */ }
      // Fallback: build a row from the tracker eval result.
      if (tracker.trackerEval && tracker.trackerEval.eval_result) {
        return {
          eval_id: tracker.trackerEval.eval_id,
          name: tracker.trackerEval.eval_name || tracker.trackerEval.eval_id,
          result: tracker.trackerEval.result,
          severity: tracker.trackerEval.severity,
          summary: tracker.trackerEval.summary,
          gap: tracker.trackerEval.eval_result.gaps && tracker.trackerEval.eval_result.gaps[0],
          control_refs: tracker.trackerEval.eval_result.controls,
        };
      }
      return null;
    })();
    if (name === "explain_for_assessor") {
      return { reasoner: name, payload: { eval_record: someEval || {} } };
    }
    if (name === "explain_for_executive") {
      const pkg = tracker.package || {};
      const summary = pkg.summary || pkg.assessment_summary || {};
      return { reasoner: name, payload: { package_summary: summary } };
    }
    if (name === "explain_conmon_reasonableness") {
      return {
        reasoner: name,
        payload: {
          conmon_result: tracker.conmonReasonableness || {
            summary: { obligations: 0, reasonable: 0, partial: 0, missing: 0, tracker_rows: tracker.rows.length },
            evidence_ecosystems: {},
            obligation_assessments: [],
          },
        },
      };
    }
    if (name === "explain_residual_risk_for_ao") {
      const f = selectedFindingForLlm();
      const pi = (tracker.package && tracker.package.poam_items) || [];
      const linkedPoam = f ? pi.find(p => p.source_finding_id === f.finding_id) : null;
      return { reasoner: name, payload: { finding: f || {}, poam: linkedPoam || null } };
    }
    if (name === "explain_derivation_trace") {
      // Only send a slice — no need to push the whole trace.
      const t = tracker.trace || {};
      return {
        reasoner: name,
        payload: {
          trace: {
            workflow: t.workflow,
            overall_status: t.overall_status,
            halted_by: t.halted_by,
            started_at: t.started_at,
            tasks: (t.tasks || []).map(x => ({
              task_id: x.task_id,
              status: x.status,
              policy_decision: x.policy_decision,
            })),
          },
        },
      };
    }
    if (name === "draft_remediation_ticket") {
      const f = selectedFindingForLlm();
      return { reasoner: name, payload: { finding: f || {}, eval_record: someEval || null } };
    }
    
    // For gap-related reasoners, use the currently selected gap (or the first one)
    const selectedGap = (tracker.gaps || []).find(g => g.gap_id === tracker.selectedGapId) || tracker.gaps[0] || {};
    
    if (name === "draft_auditor_response") {
      const q = "Show evidence of " + (selectedGap.gap_type || "the cited control") + " for the cited assets.";
      return { reasoner: name, payload: { question: q, evidence_gap: selectedGap } };
    }
    if (name === "evaluate_3pao_remediation_for_gap") {
      return { reasoner: name, payload: { evidence_gap: selectedGap } };
    }
    
    if (name === "classify_ambiguous_row") {
      const r = tracker.rows[0] || {};
      return {
        reasoner: name,
        payload: {
          tracker_row: r,
          deterministic_classification: { gap_type: "unknown", severity: "low" },
        },
      };
    }
    return { reasoner: name, payload: {} };
  }

  async function probeAiServer() {
    document.getElementById("tracker-llm-endpoint").textContent = API_BASE;
    try {
      const r = await fetch(API_BASE + "/api/health");
      document.getElementById("tracker-llm-reachable").textContent = r.ok ? "yes" : "no (" + r.status + ")";
    } catch (e) {
      document.getElementById("tracker-llm-reachable").textContent = "no";
    }
    try {
      const r = await fetch(API_BASE + "/api/ai/status");
      if (r.ok) {
        const j = await r.json();
        document.getElementById("tracker-llm-keyset").textContent = j && j.llm_configured ? "yes" : "no (deterministic fallback)";
        document.getElementById("tracker-llm-endpoint").textContent = (j && j.endpoint) || API_BASE;
      } else {
        document.getElementById("tracker-llm-keyset").textContent = "unknown";
      }
    } catch (e) {
      document.getElementById("tracker-llm-keyset").textContent = "unknown (server not running)";
    }
  }

  function renderLlmTab() {
    const contractEl = document.getElementById("tracker-llm-contract");
    if (contractEl) contractEl.innerHTML = simpleMd(EVIDENCE_CONTRACT_MD);
    const btnWrap = document.getElementById("tracker-llm-buttons");
    if (btnWrap) {
      btnWrap.innerHTML = REASONERS
        .map(r => '<button type="button" data-reasoner="' + esc(r.id) + '">' + esc(r.label) + '</button>')
        .join("");
      btnWrap.querySelectorAll("button").forEach(b => {
        b.addEventListener("click", () => runReasoner(b.getAttribute("data-reasoner")));
      });
    }
    probeAiServer();
  }

  function renderReasonerOutput(name, body) {
    const out = document.getElementById("tracker-llm-output");
    if (!out) return;
    if (!body || typeof body !== "object") {
      out.textContent = String(body || "(empty)");
      return;
    }
    const src = body.source || (body.result && body.result.source) || "deterministic_fallback";
    const pillCls = src === "llm" ? "llm" : "fallback";
    const cited = (body.citations || []).map(c =>
      "<li><code>" + esc(c.artifact || "") + "</code>" +
      (c.field ? " · field <code>" + esc(c.field) + "</code>" : "") +
      (c.note ? " — <em>" + esc(c.note) + "</em>" : "") +
      "</li>"
    ).join("");
    const missing = (body.missing_evidence || []).map(m => "<li>" + esc(m) + "</li>").join("");
    const warnings = (body.warnings || []).map(w => "<li>" + esc(w) + "</li>").join("");
    const summaryFields = [
      ["headline", body.headline],
      ["title", body.title],
      ["question", body.question],
      ["gap_type", body.gap_type],
      ["severity", body.severity],
      ["confidence", body.confidence],
      ["draft_ticket_id", body.draft_ticket_id],
      ["audience", body.audience],
      ["reasonable_test_passed", body.reasonable_test_passed],
      ["recommendation", body.recommendation],
    ].filter(p => p[1] != null).map(p => "<li><strong>" + esc(p[0]) + ":</strong> " + esc(String(p[1])) + "</li>").join("");
    const longBody = body.body || body.description_md || body.response_md || body.rationale || body.remediation_plan_md || "";
    out.innerHTML =
      "<p><strong>Reasoner:</strong> <code>" + esc(name) + "</code> " +
      "<span class='llm-pill " + pillCls + "'>" + esc(src) + "</span></p>" +
      (summaryFields ? "<ul class='plain'>" + summaryFields + "</ul>" : "") +
      (longBody ? "<h4>Output</h4><div class='mono-block'>" + esc(longBody) + "</div>" : "") +
      "<h4>Citations</h4><ul class='plain'>" + (cited || "<li>(none)</li>") + "</ul>" +
      "<h4>Missing evidence</h4><ul class='plain'>" + (missing || "<li>(none)</li>") + "</ul>" +
      (warnings ? "<h4>Warnings</h4><ul class='plain'>" + warnings + "</ul>" : "");
  }

  async function runReasoner(name) {
    const out = document.getElementById("tracker-llm-output");
    if (out) out.textContent = "Calling " + name + "…";
    const built = payloadForReasoner(name);
    try {
      const r = await fetch(API_BASE + "/api/ai/reasoner", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(built),
      });
      if (r.ok) {
        const j = await r.json();
        renderReasonerOutput(name, j);
        return;
      }
      const txt = await r.text();
      if (out) out.textContent = "Server returned " + r.status + ": " + txt.slice(0, 800);
    } catch (e) {
      if (out) out.textContent =
        "Could not reach " + API_BASE + " (" + (e && e.message) + ")\n\n" +
        "Start the API:\n" +
        "  uvicorn api.server:app --host 127.0.0.1 --port 8081\n\n" +
        "All reasoners produce a deterministic-fallback response unless AI_API_KEY is set.";
    }
  }

  // -------------------------------------------------------------------------
  // Tab 5: 20x Package
  // -------------------------------------------------------------------------

  function renderPackage() {
    const cards = document.getElementById("tracker-package-cards");
    const ksiTb = document.querySelector("#tracker-package-ksi-table tbody");
    const findingsEl = document.getElementById("tracker-package-findings");
    const poamTb = document.querySelector("#tracker-package-poam-table tbody");
    const reconEl = document.getElementById("tracker-package-recon");
    if (!cards) return;

    const pkg = tracker.package;
    if (!pkg) {
      cards.innerHTML = "<p class='warn'>No fedramp20x-package.json found in package_tracker locations.</p>";
      ksiTb.innerHTML = "";
      findingsEl.innerHTML = "";
      poamTb.innerHTML = "";
      reconEl.innerHTML = "";
      return;
    }
    const ksiRows = pkg.ksi_validation_results || [];
    const findings = pkg.findings || [];
    const poamItems = pkg.poam_items || [];
    const recon = pkg.reconciliation_summary || {};

    cards.innerHTML = [
      ["KSI total", ksiRows.length],
      ["KSI PASS", ksiRows.filter(k => String(k.status).toUpperCase() === "PASS").length],
      ["KSI PARTIAL", ksiRows.filter(k => String(k.status).toUpperCase() === "PARTIAL").length],
      ["KSI FAIL", ksiRows.filter(k => String(k.status).toUpperCase() === "FAIL").length],
      ["Findings", findings.length],
      ["POA&M items", poamItems.length],
      ["Tracker findings", findings.filter(f => String(f.finding_id || "").startsWith("FIND-TRACKER-")).length],
      ["Reconciliation", recon.overall_status || "—"],
    ]
      .map(([l, v]) => '<div class="card"><div class="label">' + esc(l) + '</div><div class="value">' + esc(String(v)) + '</div></div>')
      .join("");

    ksiTb.innerHTML = ksiRows
      .map(k => {
        const evals = (k.linked_eval_ids || []).join(", ");
        const ctrls = (k.linked_nist_control_refs || []).join(", ");
        return (
          "<tr>" +
          "<td><span class='badge " + badgeClass(k.status) + "'>" + esc(k.status || "—") + "</span></td>" +
          "<td><code>" + esc(k.ksi_id) + "</code></td>" +
          "<td>" + esc(evals || "—") + "</td>" +
          "<td>" + esc(ctrls || "—") + "</td>" +
          "</tr>"
        );
      })
      .join("");

    findingsEl.innerHTML = findings.length
      ? findings.map(f => {
          const isTracker = String(f.finding_id || "").startsWith("FIND-TRACKER-");
          return (
            '<div class="card finding-card" data-finding-id="' + esc(f.finding_id) + '" style="border-left:4px solid var(--' +
            (isTracker ? "accent" : "border") + ');">' +
            "<div class='label'>" + esc(f.finding_id) + (isTracker ? " · TRACKER" : "") + "</div>" +
            "<div class='value' style='font-size:0.95rem'>" + esc(f.title || "(no title)") + "</div>" +
            "<p style='font-size:0.78rem;color:var(--muted);margin:0.5rem 0 0'>severity " +
            "<span class='badge " + severityBadge(f.severity) + "'>" + esc(f.severity || "—") + "</span> · " +
            "ksi " + esc((f.ksi_ids || []).join(", ") || "—") + "</p>" +
            "</div>"
          );
        }).join("")
      : "<p class='warn'>No findings.</p>";
    findingsEl.querySelectorAll(".finding-card").forEach(card => {
      card.addEventListener("click", () => {
        tracker.selectedFindingId = card.getAttribute("data-finding-id");
        renderDerivation();
        // jump to derivation tab.
        const link = document.querySelector("nav a.nav-item[data-panel='tracker-derivation']");
        if (link) link.click();
      });
    });

    poamTb.innerHTML = poamItems.length
      ? poamItems.map(p =>
          "<tr>" +
          "<td><code>" + esc(p.poam_id) + "</code></td>" +
          "<td>" + esc(p.status || "—") + "</td>" +
          "<td><span class='badge " + severityBadge(p.severity || p.weakness_severity) + "'>" + esc(p.severity || p.weakness_severity || "—") + "</span></td>" +
          "<td>" + esc(((p.controls || p.control_refs) || []).join(", ") || "—") + "</td>" +
          "<td><code>" + esc(p.source_eval_id || p.source_finding_id || "—") + "</code></td>" +
          "</tr>"
        ).join("")
      : "<tr><td colspan='5' class='warn'>No POA&amp;M items.</td></tr>";

    const checks = (recon.checks || []).slice();
    reconEl.innerHTML =
      "<p><span class='badge " + badgeClass(recon.overall_status) + "'>" + esc(recon.overall_status || "—") + "</span> " +
      esc(checks.length ? checks.length + " checks" : "(no checks recorded)") + "</p>" +
      (checks.length
        ? "<ul class='plain'>" + checks.map(c =>
            "<li><span class='badge " + badgeClass(c.status) + "'>" + esc(c.status || "—") + "</span> <code>" +
            esc(c.id) + "</code> — " + esc(c.description || "") + "</li>"
          ).join("") + "</ul>"
        : "");
  }

  // -------------------------------------------------------------------------
  // Tab 6: Derivation Trace (per finding)
  // -------------------------------------------------------------------------

  function trackerDerivedFindings() {
    if (!tracker.package || !Array.isArray(tracker.package.findings)) return [];
    return tracker.package.findings.filter(f => String(f.finding_id || "").startsWith("FIND-TRACKER-"));
  }

  function renderDerivationFindingBar() {
    const wrap = document.getElementById("tracker-derivation-finding-bar");
    if (!wrap) return;
    const findings = trackerDerivedFindings();
    if (!findings.length) {
      wrap.innerHTML = "<p class='warn'>No tracker-derived findings (FIND-TRACKER-*) in the loaded package.</p>";
      return;
    }
    wrap.innerHTML = findings.map(f =>
      '<button type="button" data-deriv-id="' + esc(f.finding_id) + '"' +
      (tracker.selectedFindingId === f.finding_id ? ' class="active"' : "") + ">" +
      esc(f.finding_id) + "</button>"
    ).join("");
    wrap.querySelectorAll("button").forEach(b => {
      b.addEventListener("click", () => {
        tracker.selectedFindingId = b.getAttribute("data-deriv-id");
        renderDerivation();
        renderDerivationFindingBar();
      });
    });
  }

  function findGapForFinding(finding) {
    if (!finding) return null;
    const gid = (finding.source_evidence_gap_id || "").trim();
    if (gid) {
      return tracker.gaps.find(g => g.gap_id === gid) || null;
    }
    // Fallback: match by control ref overlap.
    const fc = new Set((finding.legacy_controls && finding.legacy_controls.rev5) || finding.controls || []);
    if (!fc.size) return null;
    return tracker.gaps.find(g => (g.controls || []).some(c => fc.has(c))) || null;
  }

  function findEvalForFinding(finding) {
    if (!finding) return null;
    const eid = finding.source_eval_id;
    if (!eid) return null;
    if (eid === (tracker.trackerEval && tracker.trackerEval.eval_id)) {
      return {
        eval_id: tracker.trackerEval.eval_id,
        name: tracker.trackerEval.eval_name,
        result: tracker.trackerEval.result,
        severity: tracker.trackerEval.severity,
        summary: tracker.trackerEval.summary,
      };
    }
    try {
      const er = window.OSAState && window.OSAState.evalResults && window.OSAState.evalResults.evaluations;
      return (er || []).find(e => e.eval_id === eid) || null;
    } catch (_) {
      return null;
    }
  }

  function findRowForGap(gap) {
    if (!gap || gap.source_item_id == null) return null;
    return tracker.rows.find(r => String(r.row_index) === String(gap.source_item_id)) || null;
  }

  function findPoamForFinding(finding) {
    if (!finding || !tracker.package) return null;
    const items = tracker.package.poam_items || [];
    return items.find(p => p.source_finding_id === finding.finding_id) || null;
  }

  function step(label, sub, body) {
    return (
      '<div class="deriv-step">' +
      '<div class="deriv-h"><strong>' + esc(label) + '</strong>' +
      (sub ? '<span class="badge missing">' + esc(sub) + "</span>" : "") + "</div>" +
      '<div class="deriv-body">' + esc(body || "—") + "</div>" +
      "</div>"
    );
  }

  function renderDerivation() {
    const out = document.getElementById("tracker-derivation-output");
    if (!out) return;
    const findings = trackerDerivedFindings();
    if (!findings.length) {
      out.innerHTML = "<p class='warn'>No tracker-derived findings to walk. Generate a package via <code>tracker-to-20x</code> or <code>run-agent --workflow tracker-to-20x</code>.</p>";
      return;
    }
    if (!tracker.selectedFindingId || !findings.some(f => f.finding_id === tracker.selectedFindingId)) {
      tracker.selectedFindingId = findings[0].finding_id;
    }
    const finding = findings.find(f => f.finding_id === tracker.selectedFindingId);
    const gap = findGapForFinding(finding);
    const row = findRowForGap(gap);
    const evRec = findEvalForFinding(finding);
    const poam = findPoamForFinding(finding);
    const ksi = (finding && finding.ksi_ids) || (gap && gap.linked_ksi_ids) || [];
    const ctrls = (finding && (finding.legacy_controls && finding.legacy_controls.rev5)) || (gap && gap.controls) || [];

    const reportLines = [];
    if (finding) reportLines.push("reports/assessor/assessor-summary.md cites " + finding.finding_id);
    if (finding) reportLines.push("reports/assessor/ksi-by-ksi-assessment.md cites linked KSI: " + ksi.join(", "));
    if (poam) reportLines.push("reports/assessor/poam.md cites " + poam.poam_id);
    if (finding) reportLines.push("reports/agency-ao/ao-risk-brief.md cites " + finding.finding_id);

    const blocks = [
      step("1 · Original tracker row",
        row ? ("row #" + row.row_index + " · " + (row.category || "—")) : "missing evidence",
        row
          ? ("controls: " + (row.controls || []).join(", ") + "\n\n" + (row.request_text || ""))
          : "(no row resolved from gap.source_item_id)"),
      step("2 · Classifier rule (deterministic) / LLM",
        gap ? ("gap_type=" + gap.gap_type + " · severity=" + gap.severity) : "—",
        gap
          ? ("recommended_artifact: " + (gap.recommended_artifact || "—") + "\n" +
             "recommended_validation: " + (gap.recommended_validation || "—") + "\n" +
             "poam_required: " + Boolean(gap.poam_required))
          : "(no EvidenceGap matched)"),
      step("3 · EvidenceGap (evidence_gaps.json)",
        gap ? gap.gap_id : "missing evidence",
        gap
          ? (gap.title + "\n" + (gap.description || ""))
          : "(none)"),
      step("4 · Eval result (eval_results.json)",
        evRec ? (evRec.eval_id + " · " + evRec.result) : "—",
        evRec
          ? ("severity: " + (evRec.severity || "—") + "\nsummary: " + (evRec.summary || ""))
          : "(no eval row resolved from finding.source_eval_id)"),
      step("5 · Control mapping",
        ctrls.length ? ctrls.join(", ") : "missing evidence",
        "Controls flow from EvidenceGap.controls and the eval row's control_refs into finding.legacy_controls."),
      step("6 · KSI mapping",
        ksi.length ? ksi.join(", ") : "—",
        "Linked via core/evidence_gap.GAP_TYPE_TO_KSI plus the eval's KSI rollup in fedramp20x-package.json."),
      step("7 · Finding (fedramp20x-package.json findings[])",
        finding ? finding.finding_id : "—",
        finding
          ? (finding.title + "\nseverity " + (finding.severity || "—") + " · status " + (finding.status || "—"))
          : "(none)"),
      step("8 · POA&M item",
        poam ? poam.poam_id : "missing evidence",
        poam
          ? ("status " + (poam.status || "—") + " · " + (poam.weakness_name || poam.title || ""))
          : "(no POA&M row references this finding)"),
      step("9 · Report sections",
        reportLines.length ? "cited" : "—",
        reportLines.join("\n")),
    ];

    out.innerHTML =
      "<h3>Selected finding: <code>" + esc(finding.finding_id) + "</code></h3>" +
      "<p>" + esc(finding.title || "") + " — severity <span class='badge " + severityBadge(finding.severity) + "'>" +
      esc(finding.severity || "—") + "</span></p>" +
      "<div class='deriv-chain'>" + blocks.join("") + "</div>";
  }

  // -------------------------------------------------------------------------
  // Boot
  // -------------------------------------------------------------------------

  async function bootstrap(sharedState) {
    // Expose shared state so the LLM tab can pull eval rows from app.js.
    if (sharedState) {
      window.OSAState = sharedState;
    }
    await loadAll();
    renderTrackerImportFilters();
    renderTrackerImportTable();
    renderTrackerImportDetail();

    renderGapFilters();
    renderGapTable();
    renderGapDetail();

    renderTrace();
    renderTraceDetail();

    renderLlmTab();

    renderPackage();
    renderDerivationFindingBar();
    renderDerivation();

    const line = document.getElementById("tracker-load-line");
    if (line) {
      const sources = [
        tracker.rowsSourceUrl ? "rows: " + tracker.rowsSourceUrl.split("/").slice(-3).join("/") : null,
        tracker.trace ? "trace ✓" : null,
        tracker.package ? "package ✓" : null,
      ].filter(Boolean);
      line.textContent = sources.length
        ? "Tracker → 20x: " + sources.join(" · ")
        : "Tracker → 20x: no artifacts found (run agent.py run-agent --workflow tracker-to-20x).";
    }
  }

  window.OSATracker = { bootstrap, _state: tracker };
})();
