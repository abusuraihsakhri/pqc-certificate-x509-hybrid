"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { evaluateLocally } = require("./app.js");

const base = {
  task_id: "TASK-1", target_identifier: "KEY-1",
  primary_metric: 1, secondary_metric: 1,
  status_descriptor: "NOMINAL", is_critical_flag: false
};

test("nominal case stays nominal", () => {
  const result = evaluateLocally(base);
  assert.equal(result.overall_urgency, "ROUTINE");
  assert.equal(result.total_alerts, 0);
  assert.equal(result.audit_hash, null);
});

test("critical plus thresholds produces three alerts", () => {
  const result = evaluateLocally({ ...base, primary_metric: 27, secondary_metric: 16,
    status_descriptor: "DISCORDANT", is_critical_flag: true });
  assert.equal(result.overall_urgency, "CRITICAL_STAT_PANIC");
  assert.equal(result.total_alerts, 3);
});

test("secondary limit without flag only raises an elevated warning", () => {
  const result = evaluateLocally({ ...base, secondary_metric: 13 });
  assert.equal(result.overall_urgency, "ELEVATED_RISK");
});

test("reject non-finite and blank inputs", () => {
  assert.throws(() => evaluateLocally({ ...base, primary_metric: "Infinity" }), /finite/);
  assert.throws(() => evaluateLocally({ ...base, task_id: "  " }), /Provide a task/);
});

test("result does not impersonate cryptographic verification", () => {
  const result = evaluateLocally(base);
  assert.equal(result.mode, "browser_demonstration");
  assert.match(result.note, /No signed audit trail/);
});
