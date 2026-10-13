"use strict";

/* Browser-only threshold demonstration. No cryptographic or PKI validation. */
const PRIMARY_LIMIT = 25;
const SECONDARY_LIMIT = 12;
const ANOMALY_TERMS = ["DISCORDANT", "ANOMALY", "MUTANT", "VIOLATION", "FAIL", "REJECT"];

function evaluateLocally(input) {
  const taskId = String(input.task_id || "").trim();
  const targetId = String(input.target_identifier || "").trim();
  const descriptor = String(input.status_descriptor || "NOMINAL").trim();
  const primary = Number(input.primary_metric);
  const secondary = Number(input.secondary_metric);
  if (!taskId || !targetId || !descriptor || taskId.length > 128 || targetId.length > 128) {
    throw new Error("Provide a task ID, target identifier and status (maximum 128 characters for identifiers).");
  }
  if (!Number.isFinite(primary) || !Number.isFinite(secondary)) {
    throw new Error("Primary and secondary measurements must be finite numbers.");
  }
  const alerts = [];
  function add(worker, urgency, summary, detail) {
    alerts.push({ origin_worker: worker, urgency, summary, technical_details: detail });
  }
  if (primary > PRIMARY_LIMIT) {
    add("InvariantQCWorker", "ELEVATED_RISK", "Primary metric threshold exceeded",
      `Primary value ${primary} exceeds configured demonstration threshold ${PRIMARY_LIMIT}.`);
  }
  if (secondary > SECONDARY_LIMIT || input.is_critical_flag === true) {
    add("SafetyEscalationWorker",
      input.is_critical_flag === true ? "CRITICAL_STAT_PANIC" : "ELEVATED_RISK",
      "Safety rule triggered", `Secondary value: ${secondary}; critical flag: ${input.is_critical_flag === true}.`);
  }
  if (ANOMALY_TERMS.some(word => descriptor.toUpperCase().includes(word))) {
    add("ProtocolConformanceWorker", "ELEVATED_RISK", "Descriptor anomaly detected",
      "Status descriptor matches a configured demonstration keyword.");
  }
  const critical = alerts.filter(a => a.urgency === "CRITICAL_STAT_PANIC").length;
  const overall = critical ? "CRITICAL_STAT_PANIC" : alerts.length ? "ELEVATED_RISK" : "ROUTINE";
  return {
    mode: "browser_demonstration",
    task_id: taskId,
    target_identifier: targetId,
    overall_urgency: overall,
    integrity_status: critical ? "RECALIBRATION_REQUIRED" :
      alerts.length ? "DISCORDANT_ANOMALY" : "VALIDATED_OPTIMAL",
    total_alerts: alerts.length,
    critical_alerts_count: critical,
    alerts,
    audit_hash: null,
    note: "Rule-based example only. Not an X.509, hybrid/PQC, chain or signature validation. No signed audit trail.",
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { evaluateLocally };
}

if (typeof document !== "undefined") {
  const form = document.getElementById("auditForm");
  const output = document.getElementById("outputConsole");
  const message = document.getElementById("modeMessage");
  const status = document.getElementById("m-status");
  const tasks = document.getElementById("m-tasks");
  const alerts = document.getElementById("m-alerts");
  const button = document.getElementById("evaluateButton");
  const exportButton = document.getElementById("exportButton");
  let lastResult = null;
  let count = 0;
  let alertCount = 0;

  form.addEventListener("submit", async event => {
    event.preventDefault();
    button.disabled = true;
    output.textContent = "Evaluating…";
    message.textContent = "";
    const data = new FormData(form);
    const input = {
      task_id: data.get("task_id"),
      target_identifier: data.get("target_identifier"),
      primary_metric: data.get("primary_metric") === "" ? NaN : Number(data.get("primary_metric")),
      secondary_metric: data.get("secondary_metric") === "" ? NaN : Number(data.get("secondary_metric")),
      status_descriptor: data.get("status_descriptor"),
      is_critical_flag: data.has("is_critical_flag"),
    };
    try {
      let result;
      if (data.has("use_api")) {
        const response = await fetch("/api/audit", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(input),
        });
        if (!response.ok) {
          let body;
          try { body = await response.json(); } catch (_) { body = {}; }
          throw new Error("API request failed (" + response.status + "): " +
            (typeof body.detail === "string" ? body.detail : "Check server configuration."));
        }
        result = await response.json();
        message.textContent = "Result returned by the local Python API. Audit signatures are held by that process.";
      } else {
        result = evaluateLocally(input);
        message.textContent = "Evaluated in this browser. No data transmitted by this application.";
      }
      lastResult = result;
      output.textContent = JSON.stringify(result, null, 2);
      count++;
      alertCount += result.total_alerts || 0;
      tasks.textContent = String(count);
      alerts.textContent = String(alertCount);
      status.textContent = result.overall_urgency || "UNKNOWN";
      exportButton.disabled = false;
    } catch (error) {
      output.textContent = "Error: " + error.message;
      message.textContent = "No result generated. No fallback result has been fabricated.";
      status.textContent = "ERROR";
    } finally {
      button.disabled = false;
    }
  });

  exportButton.addEventListener("click", () => {
    if (!lastResult) return;
    const blob = new Blob([JSON.stringify(lastResult, null, 2) + "\n"], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "audit-result.json";
    link.click();
    URL.revokeObjectURL(url);
  });
}
