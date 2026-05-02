# Coalfire-aligned demo narrative (public themes only)

**Relationship disclosure:** Any reference to Coalfire reflects **public themes** commonly discussed in cloud assurance, FedRAMP, and AI governance communities—for example after **event sponsorship** or industry panels. This project **does not** claim a business partnership, joint offering, or endorsement beyond what a sponsor relationship would explicitly allow. **No proprietary assessment framework** from any vendor is described here as something we “implemented”; alignment is **thematic** (risk transparency, evidence integrity, human-in-the-loop).

**Public-theme alignment (non-proprietary):** Independent cloud and compliance conversations—including materials attendees may associate with firms like Coalfire—often stress: **provable evidence**, **FedRAMP-oriented packaging**, **AI and automation risk**, and **defensible audit narrative**. This demo follows those **general** expectations without importing named proprietary methodologies as if they were code.

---

## Demo narrative (eight beats)

1. **AI agents are systems, not just models.**  
   The demo treats an agent as **identity + tools + context + policy + observability + response**—the same way auditors think about a workload, not a chat box in isolation.

2. **The system evaluates cloud posture and the agent operating inside that cloud.**  
   Cloud evidence (inventory, logs, alerts, tickets, changes) and **agent telemetry** (tool calls, memory events, violations) are correlated in one assessment run.

3. **It checks identity, tool use, memory/context, policy gates, logging, alerts, tickets, and POA&M.**  
   Evaluations map to explicit control-style concerns; gaps are listed, not smoothed over.

4. **It threat-hunts for shadow AI, prompt injection, unauthorized tool use, credential misuse, and agentic insider risk.**  
   Hypothesis-driven hunt output is **suspected / requires review / blocked attempt** language—no asserted compromise without primary evidence.

5. **It produces FedRAMP 20x-style machine-readable evidence and human-readable reports.**  
   JSON artifacts, gap matrices, POA&M hints, and Markdown narratives **derive from the same loaded inputs** the validator checks.

6. **It never invents missing evidence.**  
   The engine refuses to fabricate controls, findings, or cloud facts; **no invented evidence** is a core product rule.

7. **Missing evidence becomes an explicit finding or POA&M candidate.**  
   FAIL/PARTIAL rows carry gaps, recommended actions, and disposition hints—missing telemetry is **visible**, not hidden.

8. **Human approval is required for risky remediation.**  
   Risky actions stay **bounded autonomy**: automation proposes; **humans approve** material remediation, consistent with sponsor-stage messaging on AI governance.

---

## Differentiator (name it in the room)

**Observable Security Agent** is an **evidence-first proof engine**: it scores **only what you load**, ties results to **controls/KSIs and artifacts**, and **rejects incomplete FAIL/PARTIAL narratives**—so assessors get **bounded autonomy** with **no invented evidence**.

---

## Three-minute presenter script

### (0:00–0:30) Product framing — 30 sec

“We’re not pitching another generic ‘AI security’ slide. **Observable Security Agent** is a **proof engine**: it runs structured evaluations on **evidence you actually have**—cloud posture **and** the **agent system** operating in that environment. The differentiator is simple: **no invented evidence**. If something isn’t in the bundle, it shows up as a **gap or POA&M candidate**, not as confident prose. That’s **bounded autonomy**—automation that illuminates risk without pretending it saw what it didn’t.”

### (0:30–1:15) Cloud evidence chain — 45 sec

“First chain: **cloud evidence**. We normalize the primary event—say a risky network change—then walk inventory, scanner scope, central logging, alerting, cross-domain correlation, change tickets, and POA&M seeds. Every FAIL or PARTIAL has to say **what evidence was used**, **what’s missing**, and **what would close the gap**. The UI and JSON are mirrors—same facts, two audiences. Nothing here is ‘because the model thinks so’; it’s **because these files said so**.”

### (1:15–2:00) Agent security / threat-hunt chain — 45 sec

“Second chain: **agent as a system**. Registered **identity**, **allowed tools**, **memory and context** boundaries, **policy allow/block/warn**, **approval gates**, and **audit fields** like `raw_ref`. We run **agent evals** on that telemetry, then **`threat-hunt`** for patterns teams worry about in public AI-risk discussions—shadow use, **prompt injection**, unauthorized tools, credential misuse, insider-style sequences—always **suspected** or **blocked attempt** language unless logs prove more. Same rule: **no invented evidence**.”

### (2:00–2:30) FedRAMP 20x package — 30 sec

“When you need **FedRAMP 20x-style** packaging, the pipeline emits **machine-readable** bundles plus human reports—KSI linkage, validation, evidence refs, reconciliation hooks. We’re not claiming we shipped someone else’s proprietary framework; we’re showing **interoperable shapes** auditors recognize, generated from **the same run** as the cloud and agent stories.”

### (2:30–3:00) AI explanation grounded in artifacts — 30 sec

“Last beat: **AI explain**—but grounded. The assistant can draft language **only from loaded artifacts**: eval rows, POA&M, graph slices. That’s the same **bounded autonomy**: helpful narrative, **zero** permission to invent missing logs or green-check a control. If you remember one line: **differentiator = proof on loaded evidence; no invented evidence; bounded autonomy for humans and bots alike.**”

---

## Speaker guardrails (sponsor-appropriate)

- Say **“themes aligned with public discussions on cloud assurance and AI risk”**—not “we execute their methodology.”
- Say **“event sponsorship”** if you need to acknowledge Coalfire presence; do **not** imply product certification or partnership.
- Prefer **FedRAMP 20x-style** / **KSI-oriented** language over vendor-specific framework names.
