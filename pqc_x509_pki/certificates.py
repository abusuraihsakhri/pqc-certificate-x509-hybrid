"""Read-only X.509 certificate metadata inspection.

This module does not validate certificate chains, verify signatures or implement
post-quantum or composite certificate issuance.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes


MAX_CERTIFICATE_BYTES = 1024 * 1024
ML_DSA_SIGNATURE_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}


def inspect_certificate(data: bytes) -> dict[str, Any]:
    """Parse PEM/DER X.509 public certificate metadata without trusting it."""
    if not data or len(data) > MAX_CERTIFICATE_BYTES:
        raise ValueError("Certificate must be nonempty and at most 1 MiB")
    try:
        if data.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise ValueError("Invalid PEM or DER X.509 certificate") from exc

    oid = cert.signature_algorithm_oid.dotted_string
    try:
        public_key = cert.public_key()
        public_key_type = type(public_key).__name__
        public_key_bits = getattr(public_key, "key_size", None)
    except (UnsupportedAlgorithm, ValueError):
        public_key_type = "Unsupported by installed cryptography library"
        public_key_bits = None

    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number_hex": format(cert.serial_number, "x"),
        "not_valid_before_utc": not_before.isoformat(),
        "not_valid_after_utc": not_after.isoformat(),
        "currently_within_validity_period": not_before <= now <= not_after,
        "signature_algorithm_oid": oid,
        "ml_dsa_signature_algorithm": ML_DSA_SIGNATURE_OIDS.get(oid),
        "public_key_type": public_key_type,
        "public_key_bits": public_key_bits,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "extensions": [
            {"oid": ext.oid.dotted_string, "critical": ext.critical}
            for ext in cert.extensions
        ],
        "signature_verified": False,
        "chain_validated": False,
        "note": "Metadata only. No signature, chain, revocation or hybrid/PQC validation performed.",
    }
