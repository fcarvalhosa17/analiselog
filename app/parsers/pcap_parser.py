from __future__ import annotations
import subprocess
import os
import re

TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "udp.srcport",
    "udp.dstport",
    "sip.Call-ID",
    "sip.Method",
    "sip.Status-Code",
    "sip.Status-Line",
    "sip.from",
    "sip.to",
    "sip.CSeq",
    "sip.Reason",
    "sip.r-uri",
]

_TSHARK_CMD = "tshark"
_SIP_USER = re.compile(r"sip[s]?:([^@>\s;]+)@", re.IGNORECASE)
_CSEQ_PARSE = re.compile(r"(\d+)\s+(\w+)")


def _extract_user(header_value: str) -> str:
    if not header_value:
        return ""
    m = _SIP_USER.search(header_value)
    if m:
        return m.group(1)
    m = re.search(r'"([^"]+)"', header_value)
    if m:
        return m.group(1)
    return header_value.strip()


def parse_pcap(file_path: str) -> dict:
    calls: dict[str, list[dict]] = {}
    errors: list[str] = []
    total_sip_messages = 0

    field_args: list[str] = []
    for f in TSHARK_FIELDS:
        field_args += ["-e", f]

    cmd = [
        _TSHARK_CMD,
        "-r", file_path,
        "-Y", "sip",
        "-T", "fields",
        "-E", "separator=|",
        "-E", "occurrence=f",
        "-E", "quote=n",
    ] + field_args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return {
            "calls": {},
            "hangup_causes": {},
            "total_sip_messages": 0,
            "errors": ["tshark não encontrado. Certifique-se de que está instalado no container."],
        }
    except subprocess.TimeoutExpired:
        return {
            "calls": {},
            "hangup_causes": {},
            "total_sip_messages": 0,
            "errors": ["Timeout ao processar o PCAP (>60s). O arquivo pode ser muito grande."],
        }

    if result.returncode not in (0, 1, 2):
        err = result.stderr.strip()[:500] if result.stderr else "Erro desconhecido"
        return {
            "calls": {},
            "hangup_causes": {},
            "total_sip_messages": 0,
            "errors": [f"tshark retornou código {result.returncode}: {err}"],
        }

    for line in result.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < len(TSHARK_FIELDS):
            parts += [""] * (len(TSHARK_FIELDS) - len(parts))

        (
            frame_num, frame_time, ip_src, ip_dst,
            udp_src, udp_dst, call_id, sip_method,
            status_code_str, status_line, sip_from, sip_to,
            sip_cseq, sip_reason, sip_ruri,
        ) = parts[:15]

        call_id = call_id.strip()
        if not call_id:
            continue

        method = sip_method.strip().upper() if sip_method.strip() else None
        status_code: int | None = None
        status_text: str | None = None

        if status_code_str.strip():
            try:
                status_code = int(status_code_str.strip())
            except ValueError:
                pass

        if status_line.strip():
            m = re.match(r"SIP/2\.0\s+\d+\s+(.*)", status_line.strip(), re.IGNORECASE)
            if m:
                status_text = m.group(1).strip()

        if method is None and status_code is None:
            continue

        from_user = _extract_user(sip_from)
        to_user = _extract_user(sip_to)

        cseq_num: int | None = None
        cseq_method: str = method or ""
        if sip_cseq.strip():
            cm = _CSEQ_PARSE.search(sip_cseq)
            if cm:
                cseq_num = int(cm.group(1))
                cseq_method = cm.group(2).upper()

        try:
            ts = float(frame_time) if frame_time.strip() else None
        except ValueError:
            ts = None

        msg = {
            "call_id": call_id,
            "method": method,
            "status_code": status_code,
            "status_text": status_text,
            "from_user": from_user,
            "to_user": to_user,
            "cseq_num": cseq_num,
            "cseq_method": cseq_method,
            "reason": sip_reason.strip() or None,
            "raw": (
                f"Frame {frame_num} | {ip_src}:{udp_src} → {ip_dst}:{udp_dst} | "
                f"{'→ ' + (method or '') if method else '← ' + status_line.strip()}"
            ),
            "timestamp": ts,
        }

        calls.setdefault(call_id, []).append(msg)
        total_sip_messages += 1

    return {
        "calls": calls,
        "hangup_causes": {},
        "total_sip_messages": total_sip_messages,
        "errors": errors,
    }


def filter_calls(
    parsed: dict,
    call_id: str = "",
    src: str = "",
    dst: str = "",
) -> dict:
    from app.parsers.asterisk_parser import filter_calls as _filter
    return _filter(parsed, call_id, src, dst)


def save_upload(data: bytes, filename: str) -> str:
    upload_dir = "/app/uploads"
    os.makedirs(upload_dir, exist_ok=True)
    safe_name = re.sub(r"[^\w.\-]", "_", os.path.basename(filename))
    path = os.path.join(upload_dir, safe_name)
    with open(path, "wb") as f:
        f.write(data)
    return path
