# ...existing code...
"""
parse_ipv4.py — Parsing manual do cabeçalho IPv4 (defensivo)
"""
import struct
import socket

IPV4_MIN_HDR = 20

PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}


def _int_to_ip(i: int) -> str:
    try:
        return socket.inet_ntoa(i.to_bytes(4, "big"))
    except Exception:
        return "0.0.0.0"


def parse_ipv4(raw: bytes) -> dict | None:
    """
    Faz parsing defensivo do cabeçalho IPv4 a partir do início do payload (início do IP).
    Retorna None se os bytes forem insuficientes ou inválidos.
    Campos retornados (exemplo):
      {
        "version": 4,
        "ihl": 20,
        "tos": 0,
        "total_length": 60,
        "id": 0x1234,
        "flags": 2,
        "frag_offset": 0,
        "ttl": 64,
        "proto": 6,
        "proto_name": "TCP",
        "src_ip": "192.168.1.1",
        "dst_ip": "8.8.8.8",
        "inner_payload": b"...",
        "summary": "IPv4 192.168.1.1 -> 8.8.8.8 proto=TCP len=60"
      }
    """
    if len(raw) < IPV4_MIN_HDR:
        return None

    try:
        # unpack first 20 bytes
        ver_ihl, tos, total_len, identification, flags_frag, ttl, proto, hdr_chk, src, dst = struct.unpack("!BBHHHBBHII", raw[:20])
    except struct.error:
        return None

    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < IPV4_MIN_HDR:
        return None

    # assegurar que temos pelo menos o header completo nos bytes
    if len(raw) < ihl:
        return None

    # calcular fragment fields
    flags = (flags_frag >> 13) & 0x7
    frag_offset = flags_frag & 0x1FFF

    # ajustar payload segundo total_len (se for zero ou inválido, usar resto dos bytes)
    if total_len != 0 and total_len <= len(raw):
        payload = raw[ihl:total_len]
    else:
        payload = raw[ihl:]

    src_ip = _int_to_ip(src)
    dst_ip = _int_to_ip(dst)

    proto_name = PROTO_NAMES.get(proto, f"NH{proto}")

    # resumo legível
    frag_str = ""
    if frag_offset != 0 or (flags & 0x1):  # more fragments flag bit is LSB of flags field
        frag_str = f" (frag offs={frag_offset} flags={flags})"

    summary = f"IPv4 {src_ip} -> {dst_ip} proto={proto_name} len={total_len}{frag_str}"

    return {
        "version": version,
        "ihl": ihl,
        "tos": tos,
        "total_length": total_len,
        "id": identification,
        "flags": flags,
        "frag_offset": frag_offset,
        "ttl": ttl,
        "proto": proto,
        "proto_name": proto_name,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "inner_payload": payload,
        "summary": summary,
    }
# ...existing code...