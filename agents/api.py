"""
FastAPI REST API Server for Pqc Certificate X509 Hybrid.
"""
from typing import Dict, Any, List
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .base import AuditLogger, PHIGuard, SecurityException
from .models import SystemTaskPayload, ConsensusDossier
from .supervisor import SystemSupervisor

supervisor = SystemSupervisor(model_provider="mock")

app = FastAPI(
    title="Pqc Certificate X509 Hybrid API",
    description="Rule-based audit demonstrator; not an X.509 signature or chain verifier",
    version="3.0.0-ENTERPRISE",
)


class ChatRequest(BaseModel):
    query: str


@app.exception_handler(SecurityException)
def security_error(request, exc):
    return JSONResponse(status_code=400, content={"detail": "Sensitive identifier detected; submission rejected."})


@app.get("/health")
def health():
    return {"status": "HEALTHY", "service": "pqc-certificate-x509-hybrid", "domain": "Post-Quantum Cryptography & Hardware Security", "standard": "NIST FIPS 203/204/205 / ISO/IEC 17825 Standards", "version": "3.0.0-ENTERPRISE"}


@app.get("/metrics")
def metrics():
    return {
        "dossiers_processed_total": len(supervisor.dossier_registry),
        "audit_blocks_total": len(AuditLogger.get_trail()),
        "system_status": "RUNNING"
    }


@app.post("/api/audit")
def api_audit(payload: SystemTaskPayload):
    try:
        dossier = supervisor.process_task(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return dossier.to_dict()


@app.post("/api/chat")
def api_chat(req: ChatRequest):
    try:
        ans = supervisor.query_supervisory_chat(req.query)
        return {"response": ans}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/audit/logs")
def api_audit_logs():
    return {"audit_trail": AuditLogger.get_trail(), "verified": AuditLogger.verify_integrity()}

# The checked-out source includes a static UI; installed packages can use the API only.
_WEB_DIR = Path(__file__).resolve().parent.parent / "web"
if (_WEB_DIR / "index.html").is_file():
    app.mount("/", StaticFiles(directory=str(_WEB_DIR), html=True), name="console")
