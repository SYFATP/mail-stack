"""Bounded RFC 3464 parsing. Correlation is not DSN sender authentication."""
from email import policy
from email.parser import BytesHeaderParser
import re

from api.services.routing import normalize_address


def _field(block, name, limit=998):
    values = block.get_all(name, [])
    if len(values) != 1:
        return ""
    value = " ".join(str(values[0]).split())
    return value if len(value) <= limit else ""


def _recipient(value):
    kind, separator, address = value.partition(";")
    if not separator or kind.strip().lower() != "rfc822":
        return ""
    try:
        return normalize_address(address.strip())
    except ValueError:
        return ""


def parse_delivery_report(message):
    """Only inspect a top-level report, never an attached/nested report."""
    if (message.get_content_type() != "multipart/report"
            or message.get_param("report-type", "").lower() != "delivery-status"):
        return None
    parts = message.get_payload()
    if not isinstance(parts, list) or len(parts) not in {2, 3}:
        return None
    status_part = parts[1]
    if status_part.get_content_type() != "message/delivery-status":
        return None
    blocks = status_part.get_payload()
    if not isinstance(blocks, list) or not 2 <= len(blocks) <= 101:
        return None
    reporting_mta = _field(blocks[0], "Reporting-MTA")
    if not reporting_mta:
        return None
    original_id = ""
    if len(parts) == 3:
        original = parts[2]
        if original.get_content_type() == "message/rfc822":
            originals = original.get_payload()
            if isinstance(originals, list) and len(originals) == 1:
                original_id = _field(originals[0], "Message-ID")
        elif original.get_content_type() == "text/rfc822-headers":
            raw = original.get_payload(decode=True) or b""
            if len(raw) <= 64 * 1024:
                original_id = _field(BytesHeaderParser(policy=policy.default).parsebytes(raw), "Message-ID")
    if not re.fullmatch(r"<[^<>\s]{1,250}>", original_id):
        return None
    reports = []
    classes = {"failed": "5", "delayed": "4", "delivered": "2", "relayed": "2", "expanded": "2"}
    for block in blocks[1:]:
        final = _recipient(_field(block, "Final-Recipient"))
        originals = block.get_all("Original-Recipient", [])
        original = _recipient(_field(block, "Original-Recipient")) if originals else final
        action = _field(block, "Action").lower()
        status = _field(block, "Status")
        if (not final or not original or action not in classes
                or not re.fullmatch(r"[245]\.\d{1,3}\.\d{1,3}", status)
                or status[0] != classes[action]):
            continue
        reports.append({
            "recipient": original, "final_recipient": final, "action": action,
            "status_code": status, "diagnostic": _field(block, "Diagnostic-Code"),
            "reporting_mta": reporting_mta,
        })
    return {"rfc_message_id": original_id, "reports": reports} if reports else None
