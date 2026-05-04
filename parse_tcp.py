# ...existing code...
"""
parse_tcp.py — Parsing manual do cabeçalho TCP (defensivo)
"""
import struct

TCP_MIN_HDR = 20

WELL_KNOWN_PORTS = {
    80:  "HTTP",
    443: "HTTPS",
    22:  "SSH",
    21:  "FTP",
    25:  "SMTP",
    110: "POP3",
    143: "IMAP",
    3389: "RDP",
}


def _flags_str(flags_int: int) -> str:
    # flags bits: CWR|ECE|URG|ACK|PSH|RST|SYN|FIN  (we'll map common ones)
    names = []
    if flags_int & 0x0001: names.append("FIN")
    if flags_int & 0x0002: names.append("SYN")
    if flags_int & 0x0004: names.append("RST")
    if flags_int & 0x0008: names.append("PSH")
    if flags_int & 0x0010: names.append("ACK")
    if flags_int & 0x0020: names.append("URG")
    if flags_int & 0x0040: names.append("ECE")
    if flags_int & 0x0080: names.append("CWR")
    return " ".join(names) if names else "NONE"


def _http_summary(payload: bytes) -> str:
    try:
        s = payload.decode("utf-8", errors="replace")
        first = s.split("\r\n", 1)[0][:120]
        return f"HTTP | {first}"
    except Exception:
        return "HTTP (payload unreadable)"


def parse_tcp(raw_bytes: bytes) -> dict | None:
    """
    Faz parsing do segmento TCP (raw_bytes começa no TCP header).
    Retorna dicionário com campos relevantes ou None se inválido/curto.
    Campos: src_port, dst_port, seq, ack, data_offset, flags, window,
            checksum, urg_ptr, inner_payload, app_proto, summary
    """
    if not raw_bytes or len(raw_bytes) < TCP_MIN_HDR:
        return None

    try:
        src_port, dst_port, seq, ack, off_flags, window, checksum, urg = struct.unpack("!HHIIHHHH", raw_bytes[:20])
    except struct.error:
        return None

    data_offset = (off_flags >> 12) & 0xF
    hdr_len = data_offset * 4
    flags_int = off_flags & 0x01FF  # lower 9 bits include flags

    if hdr_len < TCP_MIN_HDR:
        return None
    if len(raw_bytes) < hdr_len:
        return None

    inner = raw_bytes[hdr_len:]
    app = WELL_KNOWN_PORTS.get(dst_port) or WELL_KNOWN_PORTS.get(src_port)

    summary = f"{_flags_str(flags_int)} | {src_port} -> {dst_port} | seq={seq} ack={ack} win={window}"
    if app == "HTTP" and inner:
        # try to show HTTP first line
        summary = _http_summary(inner)

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "data_offset": data_offset,
        "flags": flags_int,
        "flags_str": _flags_str(flags_int),
        "window": window,
        "checksum": checksum,
        "urg_ptr": urg,
        "inner_payload": inner,
        "app_proto": app,
        "summary": summary,
    }
# ...existing code...