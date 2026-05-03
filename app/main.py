from __future__ import annotations
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.parsers.asterisk_parser import parse_asterisk_log, filter_calls as filter_ast
from app.parsers.pcap_parser import parse_pcap, filter_calls as filter_pcap, save_upload
from app.analyzers.sip_analyzer import analyze_call, SIP_RESPONSE_CODES, Q850_CAUSES

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

app = FastAPI(title="VoIP Log Analyzer", version="1.0.0")

_static_dir = Path(__file__).parent / "static"


@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = _static_dir / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/sip-codes")
async def sip_codes():
    result = []
    for code, info in sorted(SIP_RESPONSE_CODES.items()):
        result.append({
            "code": code,
            "name": info["name"],
            "category": info["category"],
            "is_error": info["is_error"],
            "description": info["description"],
        })
    return result


def _build_response(parsed: dict, source: str, call_id: str, src: str, dst: str) -> dict:
    analyzed_calls = []
    for cid, messages in parsed["calls"].items():
        hangup_causes = parsed.get("hangup_causes", {}).get(cid, [])
        call_result = analyze_call(cid, messages, hangup_causes)
        analyzed_calls.append(call_result)

    analyzed_calls.sort(
        key=lambda c: (
            0 if c["verdict"] == "error" else 1 if c["verdict"] == "inconclusive" else 2,
            -c["message_count"],
        )
    )

    return {
        "source": source,
        "total_calls": len(analyzed_calls),
        "total_sip_messages": parsed["total_sip_messages"],
        "filters_applied": {
            "call_id": call_id,
            "src": src,
            "dst": dst,
        },
        "parse_errors": parsed.get("errors", []),
        "calls": analyzed_calls,
    }


@app.post("/api/analyze/log")
async def analyze_log(
    log_text: Optional[str] = Form(default=None),
    log_file: Optional[UploadFile] = File(default=None),
    call_id: str = Form(default=""),
    src: str = Form(default=""),
    dst: str = Form(default=""),
):
    text = ""

    if log_file is not None and log_file.filename:
        content = await log_file.read()
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Arquivo excede o limite de 50 MB")
        text = content.decode("utf-8", errors="replace")
    elif log_text:
        text = log_text
    else:
        raise HTTPException(status_code=400, detail="Forneça log_text ou log_file")

    parsed = parse_asterisk_log(text)
    filtered = filter_ast(parsed, call_id, src, dst)
    return JSONResponse(_build_response(filtered, "asterisk_log", call_id, src, dst))


@app.post("/api/analyze/pcap")
async def analyze_pcap(
    pcap_file: UploadFile = File(...),
    call_id: str = Form(default=""),
    src: str = Form(default=""),
    dst: str = Form(default=""),
):
    content = await pcap_file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Arquivo excede o limite de 50 MB")

    file_path = save_upload(content, pcap_file.filename or "upload.pcap")
    try:
        parsed = parse_pcap(file_path)
        filtered = filter_pcap(parsed, call_id, src, dst)
        return JSONResponse(_build_response(filtered, "pcap", call_id, src, dst))
    finally:
        try:
            os.remove(file_path)
        except OSError:
            pass
