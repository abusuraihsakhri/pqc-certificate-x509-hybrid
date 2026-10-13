"""Regression tests for certificate inspection, audit security and API behavior."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agents.api import app
from agents.base import AuditTrail, SecurityException
from agents.models import SystemTaskPayload
from agents.supervisor import SystemSupervisor
from pqc_x509_pki.certificates import inspect_certificate, MAX_CERTIFICATE_BYTES
from pqc_x509_pki.cli import main as package_main


@pytest.fixture
def public_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "research.example")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return cert


def test_parse_pem_der_metadata(public_certificate):
    cert = public_certificate
    pem = cert.public_bytes(serialization.Encoding.PEM)
    der = cert.public_bytes(serialization.Encoding.DER)
    one = inspect_certificate(pem)
    two = inspect_certificate(der)
    assert one == two or one["sha256_fingerprint"] == two["sha256_fingerprint"]
    assert one["subject"] == "CN=research.example"
    assert one["public_key_bits"] == 2048
    assert one["currently_within_validity_period"] is True
    assert one["signature_verified"] is False
    assert one["chain_validated"] is False


@pytest.mark.parametrize("content", [b"", b"garbage", b"x" * (MAX_CERTIFICATE_BYTES + 1)])
def test_bad_certificates_rejected(content):
    with pytest.raises(ValueError):
        inspect_certificate(content)


def test_inspection_cli(tmp_path, capsys, public_certificate):
    path = tmp_path / "leaf.pem"
    path.write_bytes(public_certificate.public_bytes(serialization.Encoding.PEM))
    assert package_main(["inspect-cert", str(path)]) == 0
    assert '"signature_verified": false' in capsys.readouterr().out
    assert package_main(["inspect-cert", str(path) + ".missing"]) == 1


def test_nonfinite_payloads_rejected():
    for metric in (float("inf"), float("-inf"), float("nan")):
        with pytest.raises(ValidationError):
            SystemTaskPayload(task_id="A", target_identifier="B", primary_metric=metric)


def test_guard_inspects_nested_attributes():
    supervisor = SystemSupervisor()
    data = SystemTaskPayload(task_id="A", target_identifier="B",
                             primary_metric=1.0,
                             attributes={"nested": {"contact": "test@example.com"}})
    with pytest.raises(SecurityException):
        supervisor.process_task(data)


def test_audit_trail_is_not_mutable_from_accessor():
    trail = AuditTrail(secret_key="local-test-key")
    trail.log("actor", "tier", "EVENT", {"safe": "data"})
    trail.get_trail()[0]["current_hash"] = "tampered"
    assert trail.verify_integrity() is True
    trail.logs[0]["current_hash"] = "tampered"
    assert trail.verify_integrity() is False


def test_api_handles_sensitive_values_and_has_static_console():
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
    response = client.post("/api/audit", json={
        "task_id": "A", "target_identifier": "B", "primary_metric": 1.0,
        "attributes": {"email": "test@example.com"}})
    assert response.status_code == 400
    assert "test@example.com" not in response.text
    response = client.post("/api/audit", json={
        "task_id": "A", "target_identifier": "B", "primary_metric": "Infinity"})
    assert response.status_code == 422
