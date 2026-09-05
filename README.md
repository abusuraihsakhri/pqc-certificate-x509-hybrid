# PQC Certificate X509 Hybrid

> **Domain:** Post-Quantum Cryptography & Zero-Knowledge Architecture
> **Reference Guidelines & Standards:** `NIST FIPS 203/204/205, NIST SP 800-90B & ISO/IEC Standards`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## What It Does

**PQC Certificate X509 Hybrid** is an analytical and computational platform implementing a Hybrid Post-Quantum PKI X.509 dual classical/PQC certificate authority agent. It provides:

- **Multi-Agent Evaluation System**: Specialized workers (InvariantQCWorker, SafetyEscalationWorker, ProtocolConformanceWorker) that evaluate task payloads against domain thresholds
- **Zero-PHI Outbound Guard**: Active pattern detection blocking SSNs, MRNs, phone numbers, emails, and patient identifiers from outbound data
- **Tamper-Evident HMAC-SHA256 Audit Trail**: Cryptographically chained, signed logs for every evaluation and state transition
- **FastAPI REST API**: OpenAPI 3.1 REST endpoints for task evaluation and system monitoring
- **CLI Interface**: Command-line tools for single task evaluation, batch processing, and server management

---

## Key Components

| Module | Description |
|:-------|:------------|
| `agents/` | Core multi-agent evaluation system with Pydantic models, workers, and supervisor |
| `pqc_x509_pki/` | PQC-X509 certificate parsing and authority engine with specialized sub-agents |
| `enrichment.py` | Domain enrichment engines for project analysis and compliance checking |
| `simulator.py` | High-throughput traffic and stress testing simulator |
| `cli.py` | Command-line interface for the main agent system |
| `web/` | Operations console web interface |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/abusuraihsakhri/pqc-certificate-x509-hybrid.git
cd pqc-certificate-x509-hybrid

# Install dependencies
pip install fastapi uvicorn pydantic pytest

# Optional: Set audit secret key for persistent audit trails
export AUDIT_SECRET_KEY="your-secure-key-here"
```

---

## Usage

### CLI Commands

#### 1. Single Task Evaluation
```bash
python cli.py audit --task-id TASK-001 --target KEY-01 --primary 28.5 --secondary 14.2 --critical --status DISCORDANT
```

#### 2. Supervisory Chat
```bash
python cli.py chat "What is the system status?"
```

#### 3. Batch Processing
```bash
python cli.py batch -i sample.csv -o results.csv
```

#### 4. Verify Audit Trail
```bash
python cli.py verify-audit
```

#### 5. Start API Server
```bash
python cli.py serve --host 127.0.0.1 --port 8000
```

### API Endpoints

| Endpoint | Method | Description |
|:---------|:-------|:------------|
| `/health` | GET | Health check |
| `/metrics` | GET | System metrics |
| `/api/audit` | POST | Submit task for evaluation |
| `/api/chat` | POST | Query supervisory chat |
| `/api/audit/logs` | GET | Get audit trail |

### Docker Deployment

```bash
docker build -t pqc-certificate-x509-hybrid .
docker run -p 8000:8000 -e AUDIT_SECRET_KEY="your-key" pqc-certificate-x509-hybrid
```

---

## Input Data Schema

| Field | Type | Description | Requirement |
|:------|:-----|:------------|:------------|
| `task_id` | str | Unique task identifier | Required |
| `target_identifier` | str | Entity or target key | Required |
| `primary_metric` | float | Primary measurement value | Required |
| `secondary_metric` | float | Secondary measurement value | Optional (default: 0.0) |
| `status_descriptor` | str | Status code or descriptor | Optional (default: "NOMINAL") |
| `is_critical_flag` | bool | Emergency escalation flag | Optional (default: false) |

---

## Testing

```bash
# Run all tests
pytest -v

# Run with coverage
pytest -v --cov=agents --cov=pqc_x509_pki

# Run simulation benchmark
python simulator.py --tasks 1000 --concurrency 8
```

---

## Security Features

- **Zero-PHI Outbound Interceptor**: AST and regex inspection blocking SSNs, MRNs, phone numbers, emails, DOB, and patient identifiers
- **Tamper-Evident HMAC-SHA256 Audit Trail**: Chained, cryptographically signed logs with signature verification
- **Secure Key Management**: Audit signing key via `AUDIT_SECRET_KEY` environment variable with secure ephemeral fallback
- **Input Validation**: Pydantic models with bounds checking and type validation

---

## License

MIT License - see [LICENSE](LICENSE) for details.
