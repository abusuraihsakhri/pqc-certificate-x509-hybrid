"""
Automated Pytest Test Suite for Pqc Certificate X509 Hybrid.
Domain: Post-Quantum Cryptography & Hardware Security
Standard: NIST FIPS 203/204/205 / ISO/IEC 17825 Standards
"""
import sys
import os
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from agents.base import PHIGuard, AuditLogger, SecurityException, AuditTrail
from agents.models import SystemTaskPayload, UrgencyLevel, SystemIntegrityStatus
from agents.workers import InvariantQCWorker, SafetyEscalationWorker, ProtocolConformanceWorker
from agents.supervisor import SystemSupervisor
from cli import main


def test_phi_guard_enforcement():
    with pytest.raises(SecurityException):
        PHIGuard.assert_no_phi("Patient MRN-994827 blood culture positive for Staphylococcus")

    # Clean text passes
    PHIGuard.assert_no_phi("Analytical assay specimen KEY-001 optimal")


def test_phi_guard_redaction():
    redacted = PHIGuard.redact_phi("Contact patient at 555-123-4567 or test@example.com")
    assert "555-123-4567" not in redacted
    assert "test@example.com" not in redacted
    assert "[REDACTED_IDENTIFIER]" in redacted


def test_specialized_workers():
    # Worker 1: QC Invariant
    p1 = SystemTaskPayload(task_id="T1", target_identifier="KEY-01", primary_metric=35.0)
    alerts1 = InvariantQCWorker.evaluate(p1)
    assert len(alerts1) == 1
    assert alerts1[0].urgency == UrgencyLevel.ELEVATED

    # Worker 2: Safety
    p2 = SystemTaskPayload(task_id="T2", target_identifier="KEY-02", primary_metric=10.0, is_critical_flag=True)
    alerts2 = SafetyEscalationWorker.evaluate(p2)
    assert len(alerts2) == 1
    assert alerts2[0].urgency == UrgencyLevel.CRITICAL_STAT

    # Worker 3: Protocol Conformance
    p3 = SystemTaskPayload(task_id="T3", target_identifier="KEY-03", primary_metric=10.0, status_descriptor="DISCORDANT_ANOMALY")
    alerts3 = ProtocolConformanceWorker.evaluate(p3)
    assert len(alerts3) == 1


def test_supervisor_consensus_and_audit():
    supervisor = SystemSupervisor(model_provider="mock")
    payload = SystemTaskPayload(
        task_id="TASK-PROD-01",
        target_identifier="KEY-PROD-01",
        primary_metric=12.0,
        secondary_metric=4.0,
        status_descriptor="NOMINAL"
    )
    dossier = supervisor.process_task(payload)
    assert dossier.overall_urgency == UrgencyLevel.ROUTINE
    assert dossier.integrity_status == SystemIntegrityStatus.VALIDATED
    assert dossier.audit_hash != ""

    # Verify cryptographic audit trail
    assert AuditLogger.verify_integrity() is True

    # CLI tests
    assert main(["audit", "--task-id", "CLI-TEST-01"]) == 0
    assert main(["chat", "Explain", "specifications"]) == 0
    assert main(["verify-audit"]) == 0


def test_audit_trail_signature_verification():
    """Test that audit trail verifies both chain linkage and HMAC signatures."""
    trail = AuditTrail(secret_key="test-secret-key")
    trail.log("test_actor", "test_tier", "TEST_EVENT", {"data": "value1"})
    trail.log("test_actor", "test_tier", "TEST_EVENT", {"data": "value2"})

    # Verify integrity passes for valid trail
    assert trail.verify_integrity() is True

    # Tamper with an entry and verify it fails
    trail.logs[0]["payload_hash"] = "tampered_hash"
    assert trail.verify_integrity() is False


def test_audit_trail_chain_linking():
    """Test that audit trail entries are properly chained."""
    trail = AuditTrail(secret_key="test-secret-key")
    entry1 = trail.log("actor1", "tier1", "EVENT1", {"data": "v1"})
    entry2 = trail.log("actor2", "tier2", "EVENT2", {"data": "v2"})

    # Second entry's prev_hash should equal first entry's current_hash
    assert entry2["prev_hash"] == entry1["current_hash"]


def test_batch_processing_file_not_found():
    """Test batch processing handles missing file gracefully."""
    result = main(["batch", "-i", "nonexistent_file.csv"])
    assert result == 1


def test_batch_processing_with_temp_file():
    """Test batch processing with a valid CSV file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
        f.write("task_id,target_identifier,primary_metric,secondary_metric,status_descriptor,is_critical_flag\n")
        f.write("T1,KEY-01,35.0,14.2,DISCORDANT,true\n")
        f.write("T2,KEY-02,12.0,4.0,NOMINAL,false\n")
        temp_path = f.name

    try:
        output_path = temp_path.replace('.csv', '_output.csv')
        result = main(["batch", "-i", temp_path, "-o", output_path])
        assert result == 0
        assert os.path.exists(output_path)

        with open(output_path, 'r') as f:
            content = f.read()
            assert "overall_urgency" in content
            assert "CRITICAL_STAT_PANIC" in content or "ELEVATED_RISK" in content

        os.unlink(output_path)
    finally:
        os.unlink(temp_path)
