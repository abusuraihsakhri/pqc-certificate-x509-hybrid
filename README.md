# PQC Certificate X509 Hybrid

A research-oriented Python audit demonstrator and read-only X.509 certificate metadata inspector.

**Scope:** The rule-based audit workers process user-supplied numeric measurements and status descriptors. Their thresholds are illustrative, not defined by NIST or IETF PKI specifications. The certificate inspector can parse public PEM/DER certificates and report fields, signature algorithm OIDs, key type, and SHA-256 fingerprint. **It does not issue certificates, verify cryptographic signatures, validate trust chains, check revocation, or establish hybrid/PQC interoperability or conformance.**

## Features

- Browser-based, offline-capable telemetry demonstration in `web/`; API use is optional and never silently simulated
- Python threshold evaluation with three workers, CLI batch CSV processing, and a FastAPI service
- Read-only X.509 metadata inspection using `cryptography`
- In-memory HMAC-SHA256 chained audit *hashes* for backend assessments, and heuristic pattern-based sensitive-identifier checks
- Automated Python and Node.js tests; Docker configuration for local use

## Use the application

When GitHub Pages is enabled and the deployment succeeds, the browser demonstration will be available from the repository's Pages deployment. The static interface can also be opened directly from `web/index.html`. Browser mode performs computations locally and does not contact a server. It does not use Pyodide because the small deterministic rule set can run directly in JavaScript without a large Python runtime.

Enter two numerical measurements and a status descriptor, choose the optional critical flag, then select **Evaluate sample**. Export JSON to download the result. To use the backend instead, run the Python API and explicitly enable **Use the local Python API** in the UI.

## Python setup

Python 3.10 or newer:

```bash
git clone https://github.com/abusuraihsakhri/pqc-certificate-x509-hybrid.git
cd pqc-certificate-x509-hybrid
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[test]"
```

For the primary audit CLI and REST API:

```bash
python cli.py audit --task-id TASK-01 --target KEY-01 --primary 28.5 --secondary 14.2 --status DISCORDANT
python cli.py batch -i sample.csv -o results.csv
python cli.py verify-audit
python cli.py serve --host 127.0.0.1 --port 8000
```

Then visit `http://127.0.0.1:8000/` for the local web UI, or `http://127.0.0.1:8000/docs` for the API documentation. Endpoints include `GET /health`, `GET /metrics`, `POST /api/audit`, `POST /api/chat`, and `GET /api/audit/logs`.

Read-only certificate inspection (public certificates only):

```bash
python cli.py inspect-cert certificate.pem
pqc-certificate-x509-hybrid inspect-cert certificate.der
```

The installed `pqc-certificate-x509-hybrid` command uses a separate, legacy threshold implementation in `pqc_x509_pki/`; it is not identical to the `python cli.py` audit API. Both commands support `inspect-cert`.

## Security and privacy

Browser evaluations remain in the browser; no request is sent unless API use is explicitly selected. Do not upload private keys or sensitive personal information. The Python API stores dossiers and audit hashes **in process memory**, not in durable storage. HMAC signatures protect recorded metadata hashes only while the secret key and unmodified records are available. The identifier-pattern filter is **not** a guarantee of HIPAA de-identification or complete PHI detection.

Provide an independent strong `AUDIT_SECRET_KEY` in your environment for server use. If no key is supplied in direct Python execution, a random ephemeral key is generated; earlier audit chains cannot be verified after restart. `docker-compose.yml` requires the key to be explicitly supplied and binds the service to loopback by default. For public deployment, add authentication, transport security, persistent signed records, and access controls.

## Testing

```bash
python -m pytest -q
python -m compileall -q agents pqc_x509_pki cli.py enrichment.py simulator.py
node --test web/app.test.cjs
node --check web/app.js
```

The browser app uses plain HTML, CSS, and JavaScript with no external libraries. Modern desktop and mobile browsers are expected to work; compatibility is tested by CI for syntax and rule evaluation, not a complete cross-browser matrix.

## License

MIT, see [LICENSE](LICENSE).
