from __future__ import annotations
import re

_CHAN_SIP_READ = re.compile(r"<---\s+SIP read from\s+\S+", re.IGNORECASE)
_CHAN_SIP_SEND = re.compile(r"--->\s+SIP (?:send|message) to\s+\S+", re.IGNORECASE)
_CHAN_PJSIP_IN = re.compile(r"<---\s+Received SIP (?:request|response|message)", re.IGNORECASE)
_CHAN_PJSIP_OUT = re.compile(r"--->\s+Sending SIP (?:request|response|message)", re.IGNORECASE)
_BLOCK_END = re.compile(r"^-{10,}\s*$")

_REQUEST_LINE = re.compile(r"^([A-Z]+)\s+sip[s]?:\S*\s+SIP/2\.0", re.IGNORECASE)
_RESPONSE_LINE = re.compile(r"^SIP/2\.0\s+(\d{3})\s+(.*)", re.IGNORECASE)
_CALL_ID = re.compile(r"^Call-ID:\s*(.+)", re.IGNORECASE | re.MULTILINE)
_FROM = re.compile(r"^From:\s*(.+)", re.IGNORECASE | re.MULTILINE)
_TO = re.compile(r"^To:\s*(.+)", re.IGNORECASE | re.MULTILINE)
_CSEQ = re.compile(r"^CSeq:\s*(\d+)\s+(\w+)", re.IGNORECASE | re.MULTILINE)
_REASON = re.compile(r"^Reason:\s*(.+)", re.IGNORECASE | re.MULTILINE)
_SIP_USER = re.compile(r"sip[s]?:([^@>\s;]+)@", re.IGNORECASE)
_HANGUP = re.compile(r"Hangup.*?cause\s*[=:]?\s*(\d+)", re.IGNORECASE)
_CALL_ID_CONTEXT = re.compile(r"Call-ID[:\s]+(\S+)", re.IGNORECASE)


def _is_block_start(line: str) -> bool:
    return bool(
        _CHAN_SIP_READ.search(line)
        or _CHAN_SIP_SEND.search(line)
        or _CHAN_PJSIP_IN.search(line)
        or _CHAN_PJSIP_OUT.search(line)
    )


def _extract_user(header_value: str) -> str:
    m = _SIP_USER.search(header_value)
    if m:
        return m.group(1)
    m = re.search(r'"([^"]+)"', header_value)
    if m:
        return m.group(1)
    return header_value.strip()


def _parse_block(block_lines: list[str]) -> dict | None:
    block = "\n".join(block_lines)

    method = None
    status_code = None
    status_text = None

    for line in block_lines:
        line = line.strip()
        if not line:
            continue
        m = _REQUEST_LINE.match(line)
        if m:
            method = m.group(1).upper()
            break
        m = _RESPONSE_LINE.match(line)
        if m:
            status_code = int(m.group(1))
            status_text = m.group(2).strip()
            break

    if method is None and status_code is None:
        return None

    call_id_m = _CALL_ID.search(block)
    if not call_id_m:
        return None
    call_id = call_id_m.group(1).strip()

    from_m = _FROM.search(block)
    from_raw = from_m.group(1).strip() if from_m else ""
    from_user = _extract_user(from_raw) if from_raw else ""

    to_m = _TO.search(block)
    to_raw = to_m.group(1).strip() if to_m else ""
    to_user = _extract_user(to_raw) if to_raw else ""

    cseq_m = _CSEQ.search(block)
    cseq_num = int(cseq_m.group(1)) if cseq_m else None
    cseq_method = cseq_m.group(2).upper() if cseq_m else (method or "")

    reason_m = _REASON.search(block)
    reason = reason_m.group(1).strip() if reason_m else None

    return {
        "call_id": call_id,
        "method": method,
        "status_code": status_code,
        "status_text": status_text,
        "from_user": from_user,
        "to_user": to_user,
        "cseq_num": cseq_num,
        "cseq_method": cseq_method,
        "reason": reason,
        "raw": block[:2000],
    }


def parse_asterisk_log(log_text: str) -> dict:
    calls: dict[str, list[dict]] = {}
    hangup_causes: dict[str, list[int]] = {}
    total_sip_messages = 0
    errors: list[str] = []
    last_call_id: str | None = None

    lines = log_text.splitlines()
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]

        hangup_m = _HANGUP.search(line)
        if hangup_m:
            cause = int(hangup_m.group(1))
            cid_m = _CALL_ID_CONTEXT.search(line)
            target_cid = cid_m.group(1).strip() if cid_m else last_call_id
            if target_cid:
                hangup_causes.setdefault(target_cid, []).append(cause)

        if _is_block_start(line):
            block_lines: list[str] = []
            i += 1
            while i < n:
                bl = lines[i]
                if _BLOCK_END.match(bl) or _is_block_start(bl):
                    break
                block_lines.append(bl)
                i += 1

            msg = _parse_block(block_lines)
            if msg:
                cid = msg["call_id"]
                calls.setdefault(cid, []).append(msg)
                last_call_id = cid
                total_sip_messages += 1
            continue

        i += 1

    return {
        "calls": calls,
        "hangup_causes": hangup_causes,
        "total_sip_messages": total_sip_messages,
        "errors": errors,
    }


def filter_calls(
    parsed: dict,
    call_id: str = "",
    src: str = "",
    dst: str = "",
) -> dict:
    if not call_id and not src and not dst:
        return parsed

    cid_lower = call_id.strip().lower()
    src_lower = src.strip().lower()
    dst_lower = dst.strip().lower()

    filtered: dict[str, list[dict]] = {}
    for cid, messages in parsed["calls"].items():
        if cid_lower and cid_lower not in cid.lower():
            continue

        if src_lower or dst_lower:
            from_users = [m.get("from_user", "").lower() for m in messages]
            to_users = [m.get("to_user", "").lower() for m in messages]

            if src_lower and not any(src_lower in u for u in from_users):
                continue
            if dst_lower and not any(dst_lower in u for u in to_users):
                continue

        filtered[cid] = messages

    return {
        "calls": filtered,
        "hangup_causes": parsed["hangup_causes"],
        "total_sip_messages": parsed["total_sip_messages"],
        "errors": parsed["errors"],
    }
